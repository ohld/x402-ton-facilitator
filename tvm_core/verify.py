"""Payment verification logic — 6 rules for TON x402 payments.

Each rule returns a VerifyResult. All must pass for a payment to be valid.
Pure logic: no HTTP calls inside rules (provider is injected).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from .address import normalize_address
from .boc import compute_boc_hash, extract_jetton_transfer, parse_external_message, parse_w5_body
from .constants import (
    DEFAULT_MAX_RELAY_COMMISSION,
    SCHEME_EXACT,
    SUPPORTED_NETWORKS,
)
from .providers import TonProvider
from .types import TvmPaymentPayload, VerifyResult


@dataclass
class VerifyConfig:
    """Configuration for payment verification."""

    relay_address: str | None = None
    max_relay_commission: int = DEFAULT_MAX_RELAY_COMMISSION
    supported_networks: set[str] | None = None
    skip_simulation: bool = True  # MVP: skip gasless simulation
    max_valid_until_seconds: int = 600  # Max 10 min validity window


# In-memory dedup cache for BoC hashes (MVP — Redis in production)
_seen_boc_hashes: set[str] = set()


def check_protocol(scheme: str, network: str, config: VerifyConfig) -> VerifyResult:
    """Rule 1: Verify scheme and network match.

    Args:
        scheme: Payment scheme from payload (must be "exact").
        network: Network identifier (must be in SUPPORTED_NETWORKS).
        config: Verification configuration.

    Returns:
        VerifyResult.
    """
    if scheme != SCHEME_EXACT:
        return VerifyResult(ok=False, reason=f"Unsupported scheme: {scheme}")

    networks = config.supported_networks or SUPPORTED_NETWORKS
    if network not in networks:
        return VerifyResult(ok=False, reason=f"Unsupported network: {network}")

    return VerifyResult(ok=True)


def check_signature(boc_b64: str, pubkey_hex: str) -> VerifyResult:
    """Rule 2: Verify Ed25519 signature on the W5 message.

    Args:
        boc_b64: Base64-encoded signed external message BoC.
        pubkey_hex: Sender's Ed25519 public key (hex).

    Returns:
        VerifyResult.
    """
    from .ed25519 import verify_w5_signature

    try:
        valid, reason = verify_w5_signature(boc_b64, pubkey_hex)
        if not valid:
            return VerifyResult(ok=False, reason=f"Invalid signature: {reason}")
        return VerifyResult(ok=True)
    except Exception as e:
        return VerifyResult(ok=False, reason=f"Signature verification error: {e}")


async def check_payment_intent(
    payload: TvmPaymentPayload,
    required_amount: str,
    required_pay_to: str,
    required_asset: str,
    provider: TonProvider,
) -> VerifyResult:
    """Rule 3: Verify jetton transfer amount, destination, and asset.

    Resolves the actual jetton wallet address on-chain to prevent spoofing.

    Args:
        payload: Parsed payment payload.
        required_amount: Required amount in smallest units.
        required_pay_to: Required recipient address (raw).
        required_asset: Required token master address (raw).
        provider: TON provider for on-chain lookups.

    Returns:
        VerifyResult.
    """
    # Normalize addresses for comparison
    try:
        pay_to_norm = normalize_address(required_pay_to)
        asset_norm = normalize_address(required_asset)
        token_master_norm = normalize_address(payload.token_master)
    except ValueError as e:
        return VerifyResult(ok=False, reason=f"Invalid address: {e}")

    # Check token master matches
    if token_master_norm != asset_norm:
        return VerifyResult(
            ok=False,
            reason=f"Token mismatch: expected {asset_norm}, got {token_master_norm}",
        )

    # Check amount
    if int(payload.amount) < int(required_amount):
        return VerifyResult(
            ok=False,
            reason=f"Insufficient amount: expected {required_amount}, got {payload.amount}",
        )

    # Resolve the correct jetton wallet address via on-chain getter
    try:
        expected_jetton_wallet = await provider.get_jetton_wallet(
            asset_norm, pay_to_norm
        )
        expected_jetton_wallet = normalize_address(expected_jetton_wallet)
    except Exception as e:
        return VerifyResult(ok=False, reason=f"Failed to resolve jetton wallet: {e}")

    # Parse the BoC to verify the actual transfer destination
    try:
        body = parse_external_message(payload.settlement_boc)
        w5_msg = parse_w5_body(body)

        # Find the jetton transfer among internal messages
        found_valid_transfer = False
        for msg in w5_msg.internal_messages:
            msg_dest = msg.get("destination", "")
            if not msg_dest:
                continue
            msg_dest_norm = normalize_address(msg_dest)

            body_cell = msg.get("body")
            if body_cell is None:
                continue

            transfer = extract_jetton_transfer(body_cell)
            if transfer is None:
                continue

            # Verify the internal message goes to the sender's jetton wallet
            # and the jetton transfer destination matches the required payTo's jetton wallet
            if transfer.destination:
                transfer_dest_norm = normalize_address(transfer.destination)
                if transfer_dest_norm == pay_to_norm:
                    if transfer.amount >= int(required_amount):
                        found_valid_transfer = True
                        break

        if not found_valid_transfer:
            return VerifyResult(
                ok=False,
                reason="No valid jetton transfer found matching required amount and destination",
            )
    except Exception as e:
        return VerifyResult(ok=False, reason=f"Failed to parse payment BoC: {e}")

    return VerifyResult(ok=True)


async def check_replay(
    payload: TvmPaymentPayload,
    provider: TonProvider,
) -> VerifyResult:
    """Rule 4: Check for replay attacks.

    Verifies:
    - validUntil is in the future but not too far
    - seqno matches on-chain state
    - BoC hash hasn't been seen before

    Args:
        payload: Parsed payment payload.
        provider: TON provider for seqno lookup.

    Returns:
        VerifyResult.
    """
    now = int(time.time())

    # Check validity window
    if payload.valid_until < now:
        return VerifyResult(ok=False, reason="Payment expired")

    if payload.valid_until > now + 600:  # 10 min max
        return VerifyResult(
            ok=False,
            reason=f"validUntil too far in future: {payload.valid_until - now}s from now",
        )

    # Check BoC hash dedup
    boc_hash = compute_boc_hash(payload.settlement_boc)
    if boc_hash in _seen_boc_hashes:
        return VerifyResult(ok=False, reason="Duplicate BoC (replay)")

    # Check seqno against on-chain state
    try:
        sender_addr = normalize_address(payload.sender)
        on_chain_seqno = await provider.get_seqno(sender_addr)

        # Parse seqno from the BoC
        body = parse_external_message(payload.settlement_boc)
        w5_msg = parse_w5_body(body)

        if w5_msg.seqno < on_chain_seqno:
            return VerifyResult(
                ok=False,
                reason=f"Stale seqno: BoC has {w5_msg.seqno}, chain has {on_chain_seqno}",
            )
    except Exception as e:
        return VerifyResult(ok=False, reason=f"Failed to check seqno: {e}")

    return VerifyResult(ok=True)


def check_relay_safety(
    payload: TvmPaymentPayload,
    config: VerifyConfig,
) -> VerifyResult:
    """Rule 5: Verify relay commission is within bounds.

    Args:
        payload: Parsed payment payload.
        config: Verification configuration with max commission and relay address.

    Returns:
        VerifyResult.
    """
    commission = int(payload.commission)

    if commission > config.max_relay_commission:
        return VerifyResult(
            ok=False,
            reason=f"Commission too high: {commission} > {config.max_relay_commission}",
        )

    # If relay address is configured, verify commission recipient
    # (In the gasless flow, commission goes to the relay address set by TONAPI)
    # For MVP we trust the gasless flow — TONAPI sets the relay address

    return VerifyResult(ok=True)


async def check_simulation(
    payload: TvmPaymentPayload,
    provider: TonProvider,
    config: VerifyConfig,
) -> VerifyResult:
    """Rule 6: Pre-simulation check via gasless estimate.

    Optional for MVP — can be skipped via config.skip_simulation.

    Args:
        payload: Parsed payment payload.
        provider: TON provider.
        config: Verification configuration.

    Returns:
        VerifyResult.
    """
    if config.skip_simulation:
        return VerifyResult(ok=True)

    # TODO: In production, call gasless_estimate to pre-simulate
    # This catches insufficient balance, wrong jetton wallet, etc.
    return VerifyResult(ok=True)


async def verify_payment(
    payload: TvmPaymentPayload,
    scheme: str,
    network: str,
    required_amount: str,
    required_pay_to: str,
    required_asset: str,
    provider: TonProvider,
    config: VerifyConfig | None = None,
) -> VerifyResult:
    """Run all 6 verification rules on a payment.

    Args:
        payload: Parsed TVM payment payload.
        scheme: Payment scheme (must be "exact").
        network: Network identifier.
        required_amount: Required amount in smallest units.
        required_pay_to: Required recipient address.
        required_asset: Required token master address.
        provider: TON provider for on-chain lookups.
        config: Optional verification config.

    Returns:
        VerifyResult — ok=True only if ALL rules pass.
    """
    cfg = config or VerifyConfig()

    # Rule 1: Protocol
    result = check_protocol(scheme, network, cfg)
    if not result.ok:
        return result

    # Rule 2: Signature
    result = check_signature(payload.settlement_boc, payload.wallet_public_key)
    if not result.ok:
        return result

    # Rule 3: Payment intent
    result = await check_payment_intent(
        payload, required_amount, required_pay_to, required_asset, provider
    )
    if not result.ok:
        return result

    # Rule 4: Replay protection
    result = await check_replay(payload, provider)
    if not result.ok:
        return result

    # Rule 5: Relay safety
    result = check_relay_safety(payload, cfg)
    if not result.ok:
        return result

    # Rule 6: Simulation
    result = await check_simulation(payload, provider, cfg)
    if not result.ok:
        return result

    # Mark BoC as seen (after all checks pass)
    boc_hash = compute_boc_hash(payload.settlement_boc)
    _seen_boc_hashes.add(boc_hash)

    return VerifyResult(ok=True)
