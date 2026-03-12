"""Core types for TON x402 payment verification."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SignedW5Message(BaseModel):
    """A signed W5 internal message (from TONAPI gasless flow)."""

    address: str
    amount: str
    payload: str = ""
    state_init: str | None = Field(default=None, alias="stateInit")

    model_config = {"populate_by_name": True}


class TvmPaymentPayload(BaseModel):
    """TON-specific payment payload sent by the client.

    The outer x402 PaymentPayload.payload dict is deserialized into this.
    """

    sender: str = Field(alias="from")
    to: str
    token_master: str = Field(alias="tokenMaster")
    amount: str
    valid_until: int = Field(alias="validUntil")
    nonce: str
    signed_messages: list[SignedW5Message] = Field(alias="signedMessages")
    commission: str = "0"
    settlement_boc: str = Field(alias="settlementBoc")
    wallet_public_key: str = Field(alias="walletPublicKey")

    model_config = {"populate_by_name": True}


class W5ParsedMessage(BaseModel):
    """Parsed contents of a W5 external message."""

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
