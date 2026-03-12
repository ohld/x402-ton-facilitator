"""TVM facilitator implementation for the Exact payment scheme.

Wraps tvm_core verification and settlement logic into the x402
SchemeNetworkFacilitator protocol interface.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from tvm_core.address import normalize_address
from tvm_core.boc import compute_boc_hash
from tvm_core.constants import SCHEME_EXACT, SUPPORTED_NETWORKS, TVM_MAINNET, TVM_TESTNET
from tvm_core.providers import TonProvider, TonSettler
from tvm_core.state import PaymentStateStore
from tvm_core.types import PaymentState, TvmPaymentPayload, VerifyResult
from tvm_core.verify import VerifyConfig, verify_payment

from ..config import TvmFacilitatorConfig

logger = logging.getLogger(__name__)


class ExactTvmFacilitatorScheme:
    """TVM facilitator for the 'exact' payment scheme.

    Implements the SchemeNetworkFacilitator protocol from x402 SDK.
    Uses tvm_core for pure verification logic and TONAPI for settlement.
    """

    scheme = SCHEME_EXACT
    caip_family = "tvm:*"

    def __init__(
        self,
        provider: TonProvider,
        settler: TonSettler,
        config: TvmFacilitatorConfig | None = None,
    ):
        self._provider = provider
        self._settler = settler
        self._config = config or TvmFacilitatorConfig()
        self._state_store = PaymentStateStore()
        self._verify_config = VerifyConfig(
            relay_address=self._config.relay_address,
            max_relay_commission=self._config.max_relay_commission,
            supported_networks=self._config.supported_networks,
        )

    def get_extra(self, network: str) -> dict[str, Any] | None:
        """Return extra data for SupportedKind.

        For TVM, we provide the relay address so clients know where to
        send commission.
        """
        if self._config.relay_address:
            return {"relayAddress": self._config.relay_address}
        return None

    def get_signers(self, network: str) -> list[str]:
        """Get signer addresses. TVM facilitator doesn't sign — returns empty."""
        return []

    async def verify(
        self,
        payload: dict[str, Any],
        requirements: dict[str, Any],
        context: Any = None,
    ) -> dict[str, Any]:
        """Verify a TVM payment payload.

        Args:
            payload: x402 PaymentPayload.payload dict.
            requirements: x402 PaymentRequirements dict.
            context: Optional facilitator context.

        Returns:
            Dict matching VerifyResponse schema.
        """
        try:
            tvm_payload = TvmPaymentPayload.model_validate(payload)
        except Exception as e:
            return {
                "is_valid": False,
                "invalid_reason": f"Invalid payload: {e}",
                "payer": None,
            }

        scheme = requirements.get("scheme", "")
        network = str(requirements.get("network", ""))
        required_amount = str(requirements.get("amount", "0"))
        required_pay_to = str(requirements.get("pay_to", ""))
        required_asset = str(requirements.get("asset", ""))
        payer = tvm_payload.sender

        result = await verify_payment(
            payload=tvm_payload,
            scheme=scheme,
            network=network,
            required_amount=required_amount,
            required_pay_to=required_pay_to,
            required_asset=required_asset,
            provider=self._provider,
            config=self._verify_config,
        )

        if result.ok:
            # Track state
            boc_hash = compute_boc_hash(tvm_payload.settlement_boc)
            record = self._state_store.get_or_create(boc_hash, payer=payer)
            if record.state == PaymentState.SEEN:
                record.transition(PaymentState.VERIFIED)

        return {
            "is_valid": result.ok,
            "invalid_reason": result.reason if not result.ok else None,
            "payer": payer,
        }

    async def settle(
        self,
        payload: dict[str, Any],
        requirements: dict[str, Any],
        context: Any = None,
    ) -> dict[str, Any]:
        """Settle a TVM payment on-chain.

        Idempotent: if already settled, returns the existing tx hash.

        Args:
            payload: x402 PaymentPayload.payload dict.
            requirements: x402 PaymentRequirements dict.
            context: Optional facilitator context.

        Returns:
            Dict matching SettleResponse schema.
        """
        try:
            tvm_payload = TvmPaymentPayload.model_validate(payload)
        except Exception as e:
            return {
                "success": False,
                "error_reason": f"Invalid payload: {e}",
                "payer": None,
                "transaction": "",
                "network": "",
            }

        payer = tvm_payload.sender
        network = str(requirements.get("network", ""))
        boc_hash = compute_boc_hash(tvm_payload.settlement_boc)

        # Idempotency: check if already settled
        already_settled, existing_tx = self._state_store.is_settled(boc_hash)
        if already_settled:
            logger.info("Payment %s already settled: %s", boc_hash[:12], existing_tx)
            return {
                "success": True,
                "transaction": existing_tx,
                "network": network,
                "payer": payer,
            }

        # Verify first
        verify_result = await self.verify(payload, requirements, context)
        if not verify_result["is_valid"]:
            return {
                "success": False,
                "error_reason": verify_result.get("invalid_reason", "Verification failed"),
                "payer": payer,
                "transaction": "",
                "network": network,
            }

        # Transition to settling
        record = self._state_store.get_or_create(boc_hash, payer=payer)
        try:
            record.transition(PaymentState.SETTLING)
        except ValueError:
            # Already past VERIFIED — might be a concurrent settle
            pass

        # Submit via gasless relay
        try:
            msg_hash = await self._settler.gasless_send(
                boc=tvm_payload.settlement_boc,
                wallet_public_key=tvm_payload.wallet_public_key,
            )

            record.tx_hash = msg_hash or boc_hash[:16]
            record.transition(PaymentState.SUBMITTED)

            # Poll for confirmation (up to settlement_timeout)
            tx_hash = await self._wait_for_confirmation(
                tvm_payload, record, timeout=self._config.settlement_timeout
            )

            if tx_hash:
                record.tx_hash = tx_hash
                record.transition(PaymentState.CONFIRMED)
                return {
                    "success": True,
                    "transaction": tx_hash,
                    "network": network,
                    "payer": payer,
                }
            else:
                # Timeout — settlement was submitted but not yet confirmed
                # Return success=True because the tx is in the mempool
                return {
                    "success": True,
                    "transaction": record.tx_hash,
                    "network": network,
                    "payer": payer,
                }

        except Exception as e:
            logger.error("Settlement failed for %s: %s", boc_hash[:12], e)
            try:
                record.transition(PaymentState.FAILED)
                record.error = str(e)
            except ValueError:
                pass

            return {
                "success": False,
                "error_reason": f"Settlement failed: {e}",
                "payer": payer,
                "transaction": "",
                "network": network,
            }

    async def _wait_for_confirmation(
        self,
        payload: TvmPaymentPayload,
        record: Any,
        timeout: int = 15,
    ) -> str | None:
        """Poll for transaction confirmation.

        Args:
            payload: Payment payload.
            record: Payment state record.
            timeout: Max seconds to wait.

        Returns:
            Transaction hash if confirmed, None if timeout.
        """
        start = time.time()
        sender = normalize_address(payload.sender)

        while time.time() - start < timeout:
            try:
                # Check if seqno advanced (indicates tx was processed)
                current_seqno = await self._provider.get_seqno(sender)
                # Parse expected seqno from BoC
                from tvm_core.boc import parse_external_message, parse_w5_body

                body = parse_external_message(payload.settlement_boc)
                w5_msg = parse_w5_body(body)

                if current_seqno > w5_msg.seqno:
                    # Seqno advanced — tx was likely processed
                    return record.tx_hash
            except Exception:
                pass

            await asyncio.sleep(2)

        return None
