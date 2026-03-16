"""TONAPI provider — implements TonProvider via tonapi.io REST API.

Used for:
- Read operations: seqno, jetton wallet resolution, account state
- Broadcast: sending signed BoCs to the network
No gasless relay dependency — the facilitator handles gas sponsorship directly.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from tvm_core.constants import TONAPI_MAINNET_URL, TONAPI_TESTNET_URL

logger = logging.getLogger(__name__)


class TonapiProvider:
    """TON provider backed by TONAPI. Implements ``TonProvider`` protocol."""

    def __init__(self, api_key: str | None = None, testnet: bool = False) -> None:
        self._base = TONAPI_TESTNET_URL if testnet else TONAPI_MAINNET_URL
        headers: dict[str, str] = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._client = httpx.AsyncClient(base_url=self._base, headers=headers)

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    async def get_seqno(self, address: str) -> int:
        resp = await self._client.get(f"/v2/wallet/{address}/seqno")
        resp.raise_for_status()
        return int(resp.json()["seqno"])

    async def get_jetton_wallet(self, master: str, owner: str) -> str:
        resp = await self._client.get(
            f"/v2/blockchain/accounts/{master}/methods/get_wallet_address",
            params={"args": [owner]},
        )
        resp.raise_for_status()
        stack = resp.json().get("decoded", {})
        return stack.get("jetton_wallet_address", stack.get("address", ""))

    async def get_account_state(self, address: str) -> dict[str, Any]:
        resp = await self._client.get(f"/v2/accounts/{address}")
        resp.raise_for_status()
        data = resp.json()
        return {
            "balance": int(data["balance"]),
            "status": data["status"],
            "code_hash": data.get("code_hash", ""),
        }

    async def get_transaction(self, tx_hash: str) -> dict[str, Any] | None:
        resp = await self._client.get(f"/v2/blockchain/transactions/{tx_hash}")
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Emulation
    # ------------------------------------------------------------------

    async def emulate(self, boc_b64: str) -> dict[str, Any] | None:
        """Emulate a transaction to estimate gas fees.

        Returns the trace with per-hop fees, or None on failure.
        """
        resp = await self._client.post(
            "/v2/wallet/emulate",
            json={"boc": boc_b64},
        )
        if resp.status_code >= 400:
            logger.warning("emulate failed: %s %s", resp.status_code, resp.text[:200])
            return None
        return resp.json()

    # ------------------------------------------------------------------
    # Broadcast
    # ------------------------------------------------------------------

    async def send_boc(self, boc_b64: str) -> bool:
        """Broadcast a signed BoC to the TON network."""
        resp = await self._client.post(
            "/v2/blockchain/message",
            json={"boc": boc_b64},
        )
        if resp.status_code >= 400:
            logger.error("send_boc failed: %s %s", resp.status_code, resp.text)
            return False
        return True
