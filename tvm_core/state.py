"""Payment state machine for idempotent settlement.

Keyed by boc_hash — ensures that duplicate settle() calls return
the same result without re-submitting to the network.

MVP: in-memory dict. Production: Redis backend.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .types import PaymentState


@dataclass
class PaymentRecord:
    """Tracks the lifecycle of a single payment."""

    boc_hash: str
    state: PaymentState = PaymentState.SEEN
    tx_hash: str = ""
    payer: str = ""
    error: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def transition(self, new_state: PaymentState) -> None:
        """Transition to a new state with validation."""
        valid_transitions = {
            PaymentState.SEEN: {PaymentState.VERIFIED, PaymentState.FAILED},
            PaymentState.VERIFIED: {PaymentState.SETTLING, PaymentState.FAILED},
            PaymentState.SETTLING: {PaymentState.SUBMITTED, PaymentState.FAILED},
            PaymentState.SUBMITTED: {
                PaymentState.CONFIRMED,
                PaymentState.FAILED,
                PaymentState.EXPIRED,
            },
            PaymentState.CONFIRMED: set(),  # terminal
            PaymentState.FAILED: set(),  # terminal
            PaymentState.EXPIRED: set(),  # terminal
        }

        allowed = valid_transitions.get(self.state, set())
        if new_state not in allowed:
            raise ValueError(
                f"Invalid state transition: {self.state} -> {new_state}"
            )

        self.state = new_state
        self.updated_at = time.time()


class PaymentStateStore:
    """In-memory payment state store.

    Thread-safe for single-process async usage (no true concurrency in asyncio).
    """

    def __init__(self) -> None:
        self._records: dict[str, PaymentRecord] = {}

    def get(self, boc_hash: str) -> PaymentRecord | None:
        return self._records.get(boc_hash)

    def get_or_create(self, boc_hash: str, payer: str = "") -> PaymentRecord:
        if boc_hash not in self._records:
            self._records[boc_hash] = PaymentRecord(boc_hash=boc_hash, payer=payer)
        return self._records[boc_hash]

    def is_settled(self, boc_hash: str) -> tuple[bool, str]:
        """Check if a payment is already settled.

        Returns:
            (True, tx_hash) if confirmed/submitted, (False, "") otherwise.
        """
        record = self._records.get(boc_hash)
        if record is None:
            return False, ""
        if record.state in (PaymentState.SUBMITTED, PaymentState.CONFIRMED):
            return True, record.tx_hash
        return False, ""

    def cleanup_expired(self, max_age_seconds: int = 3600) -> int:
        """Remove records older than max_age_seconds. Returns count removed."""
        now = time.time()
        expired = [
            k
            for k, v in self._records.items()
            if now - v.created_at > max_age_seconds
        ]
        for k in expired:
            del self._records[k]
        return len(expired)
