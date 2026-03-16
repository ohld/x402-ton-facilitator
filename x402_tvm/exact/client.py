"""TVM client implementation for the Exact payment scheme.

In the self-relay architecture, the client:
1. Calls facilitator /prepare to get seqno + messages
2. Signs locally with authType='internal'
3. Sends the signed BoC as part of the x402 payment header

Zero blockchain API calls from the client.
"""

from __future__ import annotations

import secrets
from typing import Any

import httpx

from ..config import TvmClientConfig


class ExactTvmClientScheme:
    """TVM client for the 'exact' payment scheme.

    Uses the facilitator's /prepare endpoint instead of direct blockchain access.
    """

    def __init__(
        self,
        wallet_address: str,
        public_key: str,
        sign_fn: Any,
        config: TvmClientConfig | None = None,
    ):
        self._wallet_address = wallet_address
        self._public_key = public_key
        self._sign_fn = sign_fn
        self._config = config or TvmClientConfig()

    async def create_payment_payload(
        self,
        requirements: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a signed TVM payment payload.

        1. Call facilitator /prepare for seqno + messages
        2. Sign with W5 wallet (authType='internal')
        3. Return payload for x402 header
        """
        pay_to = str(requirements["payTo"])
        asset = str(requirements["asset"])
        amount = str(requirements["amount"])

        # Call facilitator /prepare
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._config.facilitator_url}/prepare",
                json={
                    "walletAddress": self._wallet_address,
                    "walletPublicKey": self._public_key,
                    "paymentRequirements": requirements,
                },
            )
            resp.raise_for_status()
            prepare_data = resp.json()

        # Sign the W5 transfer
        settlement_boc = await self._sign_fn(
            seqno=prepare_data["seqno"],
            valid_until=prepare_data["validUntil"],
            messages=prepare_data["messages"],
        )

        return {
            "from": self._wallet_address,
            "to": pay_to,
            "tokenMaster": asset,
            "amount": amount,
            "validUntil": prepare_data["validUntil"],
            "nonce": secrets.token_hex(16),
            "settlementBoc": settlement_boc,
            "walletPublicKey": self._public_key,
        }
