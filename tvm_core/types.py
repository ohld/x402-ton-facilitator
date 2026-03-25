"""Core types for TON x402 payment verification."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class TvmPaymentPayload(BaseModel):
    """TON-specific payment payload sent by the client.

    Minimal: only settlementBoc (internal message BoC) and asset (token master).
    All other fields (from, to, amount, publicKey) are derived from the BoC.
    """

    settlement_boc: str = Field(alias="settlementBoc")
    asset: str  # Jetton master contract address (raw format)

    model_config = {"populate_by_name": True}


class PrepareRequest(BaseModel):
    """Request body for /prepare endpoint."""

    wallet_address: str = Field(alias="walletAddress")
    wallet_public_key: str = Field(alias="walletPublicKey")
    payment_requirements: dict[str, Any] = Field(alias="paymentRequirements")

    model_config = {"populate_by_name": True}


class PrepareResponse(BaseModel):
    """Response from /prepare — everything the client needs to sign."""

    seqno: int
    valid_until: int = Field(alias="validUntil")
    wallet_id: int = Field(alias="walletId")
    messages: list[dict[str, Any]]

    model_config = {"populate_by_name": True}


class W5ParsedMessage(BaseModel):
    """Parsed contents of a W5 signed message body."""

    seqno: int
    valid_until: int
    internal_messages: list[dict[str, Any]]
    raw_body_hash: str


class JettonTransferInfo(BaseModel):
    """Extracted jetton transfer details from an internal message."""

    destination: str
    amount: int
    response_destination: str | None = None
    forward_ton_amount: int = 0
    jetton_wallet: str = ""


class SettlementData(BaseModel):
    """Parsed settlement BoC (internal message format)."""

    sender_address: str  # dest of the internal message = client wallet
    body_cell: Any  # Cell — the W5 signed body
    state_init_cell: Any | None = None  # Cell — optional stateInit for deployment

    model_config = {"arbitrary_types_allowed": True}


class VerifyResult(BaseModel):
    """Result of a single verification check."""

    ok: bool
    reason: str = ""


class PaymentState(str, Enum):
    """Payment lifecycle states."""

    SEEN = "seen"
    VERIFIED = "verified"
    SETTLING = "settling"
    SUBMITTED = "submitted"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    EXPIRED = "expired"
