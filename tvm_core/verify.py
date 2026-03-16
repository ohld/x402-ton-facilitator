"""Payment verification logic — 5 rules for TON x402 payments.

Each rule returns a VerifyResult. All must pass for a payment to be valid.
Pure logic: no HTTP calls inside rules (provider is injected).

Rules:
1. Protocol: scheme and network match
2. Signature: valid Ed25519 on W5 message
3. Payment intent: jetton transfer amount, destination, asset match
4. Replay protection: seqno, validUntil, BoC hash dedup
5. Simulation: optional pre-simulation check
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .address import normalize_address
from .boc import compute_boc_hash, extract_jetton_transfer, parse_external_message, parse_w5_body
from .constants import SCHEME_EXACT, SUPPORTED_NETWORKS
from .providers import TonProvider
from .types import TvmPaymentPayload, VerifyResult


@dataclass
class VerifyConfig:
    """Configuration for payment verification."""

    supported_networks: set[str] | None = None
    skip_simulation: bool = True  # MVP: skip simulation
    max_valid_until_seconds: int = 600  # Max 10 min validity window


# In-memory dedup cache for BoC hashes (MVP — Redis in production)
_seen_boc_hashes: set[str] = set()


def check_protocol(scheme: str, network: str, config: VerifyConfig) -> VerifyResult:
    """Rule 1: Verify scheme and network match."""
    if scheme != SCHEME_EXACT:
        return VerifyResult(ok=False, reason=f"Unsupported scheme: {scheme}")

    networks = config.supported_networks or SUPPORTED_NETWORKS
    if network not in networks:
        return VerifyResult(ok=False, reason=f"Unsupported network: {network}")

    return VerifyResult(ok=True)


def check_signature(boc_b64: str, pubkey_hex: str) -> VerifyResult:
    """Rule 2: Verify Ed25519 signature on the W5 message."""
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

    Expects exactly 1 jetton_transfer action in the signed message.
    """
    try:
        pay_to_norm = normalize_address(required_pay_to)
        asset_norm = normalize_address(required_asset)
        token_master_norm = normalize_address(payload.token_master)
    except ValueError as e:
        return VerifyResult(ok=False, reason=f"Invalid address: {e}")

    if token_master_norm != asset_norm:
        return VerifyResult(
            ok=False,
            reason=f"Token mismatch: expected {asset_norm}, got {token_master_norm}",
        )

    if int(payload.amount) < int(required_amount):
        return VerifyResult(
            ok=False,
            reason=f"Insufficient amount: expected {required_amount}, got {payload.amount}",
        )

    # Parse the BoC to verify the actual transfer destination
    try:
        body = parse_external_message(payload.settlement_boc)
        w5_msg = parse_w5_body(body)

        # Find jetton transfers among internal messages
        found_valid_transfer = False
        jetton_transfer_count = 0
        for msg in w5_msg.internal_messages:
            body_cell = msg.get("body")
            if body_cell is None:
                continue

            transfer = extract_jetton_transfer(body_cell)
            if transfer is None:
                continue

            jetton_transfer_count += 1

            if transfer.destination:
                transfer_dest_norm = normalize_address(transfer.destination)
                if transfer_dest_norm == pay_to_norm:
                    if transfer.amount >= int(required_amount):
                        found_valid_transfer = True

        if not found_valid_transfer:
            return VerifyResult(
                ok=False,
                reason="No valid jetton transfer found matching required amount and destination",
            )

        # Self-relay model: expect exactly 1 jetton transfer (no relay commission)
        if jetton_transfer_count > 1:
            return VerifyResult(
                ok=False,
                reason=f"Expected 1 jetton transfer, found {jetton_transfer_count}",
            )

    except Exception as e:
        return VerifyResult(ok=False, reason=f"Failed to parse payment BoC: {e}")

    return VerifyResult(ok=True)


async def check_replay(
    payload: TvmPaymentPayload,
    provider: TonProvider,
) -> VerifyResult:
    """Rule 4: Check for replay attacks."""
    now = int(time.time())

    if payload.valid_until < now:
        return VerifyResult(ok=False, reason="Payment expired")

    if payload.valid_until > now + 600:  # 10 min max
        return VerifyResult(
            ok=False,
            reason=f"validUntil too far in future: {payload.valid_until - now}s from now",
        )

    boc_hash = compute_boc_hash(payload.settlement_boc)
    if boc_hash in _seen_boc_hashes:
        return VerifyResult(ok=False, reason="Duplicate BoC (replay)")

    try:
        sender_addr = normalize_address(payload.sender)
        on_chain_seqno = await provider.get_seqno(sender_addr)

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


async def check_simulation(
    payload: TvmPaymentPayload,
    provider: TonProvider,
    config: VerifyConfig,
) -> VerifyResult:
    """Rule 5: Pre-simulation check (optional)."""
    if config.skip_simulation:
        return VerifyResult(ok=True)

    # TODO: In production, use emulation API to pre-simulate
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
    """Run all verification rules on a payment.

    Returns ok=True only if ALL rules pass.
    """
    cfg = config or VerifyConfig()

    result = check_protocol(scheme, network, cfg)
    if not result.ok:
        return result

    result = check_signature(payload.settlement_boc, payload.wallet_public_key)
    if not result.ok:
        return result

    result = await check_payment_intent(
        payload, required_amount, required_pay_to, required_asset, provider
    )
    if not result.ok:
        return result

    result = await check_replay(payload, provider)
    if not result.ok:
        return result

    result = await check_simulation(payload, provider, cfg)
    if not result.ok:
        return result

    # Mark BoC as seen (after all checks pass)
    boc_hash = compute_boc_hash(payload.settlement_boc)
    _seen_boc_hashes.add(boc_hash)

    return VerifyResult(ok=True)
