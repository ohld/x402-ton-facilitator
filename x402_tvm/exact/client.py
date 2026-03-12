"""TVM client implementation for the Exact payment scheme.

Creates signed W5 payment payloads for TON x402 payments.
Uses TONAPI gasless flow for fee estimation.
"""

from __future__ import annotations

import secrets
import time
from typing import Any

from tvm_core.address import normalize_address
from tvm_core.constants import SCHEME_EXACT
from tvm_core.providers import TonProvider, TonSettler

from ..config import TvmClientConfig


class ExactTvmClientScheme:
    """TVM client for the 'exact' payment scheme.

    Implements the SchemeNetworkClient protocol from x402 SDK.
    Creates payment payloads using TONAPI gasless flow.
    """

    scheme = SCHEME_EXACT

    def __init__(
        self,
        wallet_address: str,
        public_key: str,
        sign_fn: Any,
        provider: TonProvider,
        settler: TonSettler,
        config: TvmClientConfig | None = None,
    ):
        """Initialize TVM client scheme.

        Args:
            wallet_address: Sender W5 wallet address (any format).
            public_key: Ed25519 public key (hex).
            sign_fn: Callable that takes (seqno, valid_until, messages) and returns
                     base64-encoded signed external message BoC.
            provider: TON provider for seqno/jetton wallet lookup.
            settler: TON settler for gasless estimation.
            config: Optional client config.
        """
        self._wallet_address = normalize_address(wallet_address)
        self._public_key = public_key
        self._sign_fn = sign_fn
        self._provider = provider
        self._settler = settler
        self._config = config or TvmClientConfig()

    async def create_payment_payload(
        self,
        requirements: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a signed TVM payment payload.

        This orchestrates the full gasless payment flow:
        1. Build jetton transfer message
        2. Get gasless estimate from TONAPI
        3. Sign the W5 transfer with all estimated messages
        4. Return the payload for x402 header

        Args:
            requirements: PaymentRequirements dict with scheme, network, asset,
                         amount, pay_to, etc.

        Returns:
            Inner payload dict for x402 PaymentPayload.
        """
        pay_to = str(requirements["pay_to"])
        asset = str(requirements["asset"])
        amount = str(requirements["amount"])

        # Get current seqno
        seqno = await self._provider.get_seqno(self._wallet_address)

        # Resolve sender's jetton wallet
        jetton_wallet = await self._provider.get_jetton_wallet(
            asset, self._wallet_address
        )

        # Build jetton transfer message for gasless estimation
        # The sign_fn is expected to handle this — we pass the parameters
        valid_until = int(time.time()) + 300  # 5 min validity
        nonce = secrets.token_hex(16)

        # Get gasless estimate
        estimate = await self._settler.gasless_estimate(
            wallet_address=self._wallet_address,
            wallet_public_key=self._public_key,
            jetton_master=asset,
            messages=[{
                "address": jetton_wallet,
                "amount": "0",
                "destination": pay_to,
                "jetton_amount": amount,
            }],
        )

        # Sign the complete W5 transfer (with all estimated messages)
        estimated_messages = estimate.get("messages", [])
        settlement_boc = await self._sign_fn(
            seqno=seqno,
            valid_until=valid_until,
            messages=estimated_messages,
        )

        # Extract commission from estimate
        commission = str(estimate.get("commission", "0"))

        return {
            "from": self._wallet_address,
            "to": pay_to,
            "tokenMaster": asset,
            "amount": amount,
            "validUntil": valid_until,
            "nonce": nonce,
            "signedMessages": estimated_messages,
            "commission": commission,
            "settlementBoc": settlement_boc,
            "walletPublicKey": self._public_key,
        }
