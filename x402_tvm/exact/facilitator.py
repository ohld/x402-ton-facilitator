"""TVM facilitator implementation for the Exact payment scheme.

Self-relay architecture: the facilitator sponsors gas for user payments
by sending internal messages with TON attached.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from tvm_core.address import normalize_address
from tvm_core.boc import compute_boc_hash, parse_settlement_boc, parse_w5_body
from tvm_core.constants import SCHEME_EXACT
from tvm_core.providers import TonProvider
from tvm_core.self_relay import SelfRelay
from tvm_core.state import PaymentStateStore
from tvm_core.types import PaymentState, TvmPaymentPayload, VerifyResult
from tvm_core.verify import VerifyConfig, verify_payment

from ..config import TvmFacilitatorConfig

logger = logging.getLogger(__name__)


class ExactTvmFacilitatorScheme:
    """TVM facilitator for the 'exact' payment scheme."""

    scheme = SCHEME_EXACT

    def __init__(
        self,
        provider: TonProvider,
        config: TvmFacilitatorConfig | None = None,
    ):
        self._provider = provider
        self._config = config or TvmFacilitatorConfig()
        self._state_store = PaymentStateStore()
        self._verify_config = VerifyConfig(
            supported_networks=self._config.supported_networks,
        )

        self._relay: SelfRelay | None = None
        if self._config.facilitator_private_key:
            self._relay = SelfRelay(
                provider=provider,
                private_key_hex=self._config.facilitator_private_key,
                gas_amount=self._config.gas_amount,
            )

    @property
    def relay(self) -> SelfRelay | None:
        return self._relay

    def _derive_payer(self, payload: TvmPaymentPayload) -> str:
        """Derive payer address from settlement BoC."""
        try:
            settlement = parse_settlement_boc(payload.settlement_boc)
            return settlement.sender_address
        except Exception:
            return ""

    async def prepare(
        self,
        wallet_address: str,
        wallet_public_key: str,
        requirements: dict[str, Any],
    ) -> dict[str, Any]:
        """Prepare signing data for a client."""
        pay_to = str(requirements.get("payTo", requirements.get("pay_to", "")))
        asset = str(requirements.get("asset", ""))
        amount = str(requirements.get("amount", "0"))

        if not self._relay:
            raise RuntimeError("Facilitator private key not configured")

        return await self._relay.prepare(
            wallet_address=wallet_address,
            pay_to=pay_to,
            token_master=asset,
            amount=amount,
        )

    async def verify(
        self,
        payload: dict[str, Any],
        requirements: dict[str, Any],
    ) -> dict[str, Any]:
        """Verify a TVM payment payload."""
        try:
            tvm_payload = TvmPaymentPayload.model_validate(payload)
        except Exception as e:
            return {
                "isValid": False,
                "invalidReason": f"Invalid payload: {e}",
                "payer": None,
            }

        payer = self._derive_payer(tvm_payload)

        scheme = requirements.get("scheme", "")
        network = str(requirements.get("network", ""))
        required_amount = str(requirements.get("amount", "0"))
        required_pay_to = str(requirements.get("payTo", requirements.get("pay_to", "")))
        required_asset = str(requirements.get("asset", ""))

        verify_config = self._verify_config
        max_timeout = requirements.get("maxTimeoutSeconds")
        if max_timeout is not None:
            verify_config = VerifyConfig(
                supported_networks=self._verify_config.supported_networks,
                skip_simulation=self._verify_config.skip_simulation,
                max_valid_until_seconds=int(max_timeout),
            )

        fac_address = self._relay.address if self._relay else None
        result = await verify_payment(
            payload=tvm_payload,
            scheme=scheme,
            network=network,
            required_amount=required_amount,
            required_pay_to=required_pay_to,
            required_asset=required_asset,
            provider=self._provider,
            config=verify_config,
            facilitator_address=fac_address,
        )

        if result.ok:
            boc_hash = compute_boc_hash(tvm_payload.settlement_boc)
            record = self._state_store.get_or_create(boc_hash, payer=payer)
            if record.state == PaymentState.SEEN:
                record.transition(PaymentState.VERIFIED)

        return {
            "isValid": result.ok,
            "invalidReason": result.reason if not result.ok else None,
            "payer": payer,
        }

    async def settle(
        self,
        payload: dict[str, Any],
        requirements: dict[str, Any],
    ) -> dict[str, Any]:
        """Settle a TVM payment on-chain via self-relay. Idempotent."""
        try:
            tvm_payload = TvmPaymentPayload.model_validate(payload)
        except Exception as e:
            return {
                "success": False,
                "errorReason": f"Invalid payload: {e}",
                "payer": None,
                "transaction": "",
                "network": "",
            }

        if not self._relay:
            return {
                "success": False,
                "errorReason": "Facilitator private key not configured",
                "payer": self._derive_payer(tvm_payload),
                "transaction": "",
                "network": str(requirements.get("network", "")),
            }

        payer = self._derive_payer(tvm_payload)
        network = str(requirements.get("network", ""))
        boc_hash = compute_boc_hash(tvm_payload.settlement_boc)

        # Idempotency
        already_settled, existing_tx = self._state_store.is_settled(boc_hash)
        if already_settled:
            return {
                "success": True,
                "transaction": existing_tx,
                "network": network,
                "payer": payer,
            }

        # Always re-verify before settlement
        verify_result = await self.verify(payload, requirements)
        if not verify_result["isValid"]:
            return {
                "success": False,
                "errorReason": verify_result.get("invalidReason", "Verification failed"),
                "payer": payer,
                "transaction": "",
                "network": network,
            }

        record = self._state_store.get_or_create(boc_hash, payer=payer)
        try:
            record.transition(PaymentState.SETTLING)
        except ValueError:
            pass

        try:
            tx_id = await self._relay.relay(
                settlement_boc=tvm_payload.settlement_boc,
            )

            record.tx_hash = tx_id or boc_hash[:16]
            record.transition(PaymentState.SUBMITTED)

            tx_hash = await self._wait_for_confirmation(
                tvm_payload, payer, record, timeout=self._config.settlement_timeout
            )

            if tx_hash:
                record.tx_hash = tx_hash
                record.transition(PaymentState.CONFIRMED)

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
                "errorReason": f"Settlement failed: {e}",
                "payer": payer,
                "transaction": "",
                "network": network,
            }

    async def _wait_for_confirmation(self, payload, payer, record, timeout=15) -> str | None:
        """Poll for transaction confirmation by checking seqno advancement."""
        start = time.time()
        sender = normalize_address(payer)

        settlement = parse_settlement_boc(payload.settlement_boc)
        w5_msg = parse_w5_body(settlement.body_cell)

        while time.time() - start < timeout:
            try:
                current_seqno = await self._provider.get_seqno(sender)
                if current_seqno > w5_msg.seqno:
                    return record.tx_hash
            except Exception:
                pass
            await asyncio.sleep(2)

        return None
