"""Abstract provider interfaces for TON blockchain interaction.

TonProvider: read operations (verification) + broadcast.
The self-relay facilitator handles gas sponsorship directly — no separate
gasless relay service is needed.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class TonProvider(Protocol):
    """TON blockchain operations for payment verification and settlement."""

    async def get_seqno(self, address: str) -> int:
        """Get current seqno for a wallet address."""
        ...

    async def get_jetton_wallet(self, master: str, owner: str) -> str:
        """Resolve jetton wallet address for an owner."""
        ...

    async def get_account_state(self, address: str) -> dict[str, Any]:
        """Get account state including balance and status."""
        ...

    async def get_transaction(self, tx_hash: str) -> dict[str, Any] | None:
        """Get transaction by hash."""
        ...

    async def send_boc(self, boc_b64: str) -> bool:
        """Broadcast a signed BoC to the network.

        Args:
            boc_b64: Base64-encoded BoC of a signed external message.

        Returns:
            True if accepted by the network.
        """
        ...
