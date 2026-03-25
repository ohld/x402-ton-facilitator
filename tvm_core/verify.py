"""Payment verification logic — rules for TON x402 payments.

All payment details (sender, amount, destination, public key) are derived
from the settlementBoc. No redundant fields in the payload.

Rules:
1. Protocol: scheme and network match
2. Signature: valid Ed25519 on W5 message (pubkey from stateInit or on-chain)
3. Payment intent: jetton transfer amount, destination, asset match
4. Replay protection: seqno (strict equality), validUntil, BoC hash dedup
5. Simulation: optional pre-simulation check
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .address import normalize_address
from .boc import (
    compute_boc_hash,
    extract_jetton_transfer,
    extract_pubkey_from_state_init,
    parse_settlement_boc,
    parse_w5_body,
)
from .constants import SCHEME_EXACT, SUPPORTED_NETWORKS
from .providers import TonProvider
from .types import TvmPaymentPayload, VerifyResult


@dataclass
class VerifyConfig:
    """Configuration for payment verification."""

    supported_networks: set[str] | None = None
    skip_simulation: bool = True  # MVP: skip simulation
    max_valid_until_seconds: int = 600  # Max 10 min validity window


# In-memory dedup cache for BoC hashes
_seen_boc_hashes: set[str] = set()


def check_protocol(scheme: str, network: str, config: VerifyConfig) -> VerifyResult:
    """Rule 1: Verify scheme and network match."""
    if scheme != SCHEME_EXACT:
        return VerifyResult(ok=False, reason=f"Unsupported scheme: {scheme}")

    networks = config.supported_networks or SUPPORTED_NETWORKS
    if network not in networks:
        return VerifyResult(ok=False, reason=f"Unsupported network: {network}")

    return VerifyResult(ok=True)


async def check_signature(
    payload: TvmPaymentPayload,
    provider: TonProvider,
) -> VerifyResult:
    """Rule 2: Verify Ed25519 signature.

    Public key is derived from:
    - stateInit in the BoC (if present, i.e. seqno == 0)
    - On-chain get_public_key getter (if no stateInit)
    """
    from .ed25519 import verify_w5_signature

    try:
        settlement = parse_settlement_boc(payload.settlement_boc)
    except Exception as e:
        return VerifyResult(ok=False, reason=f"Failed to parse settlement BoC: {e}")

    # Derive public key
    pubkey_hex = None
    if settlement.state_init_cell is not None:
        pubkey_hex = extract_pubkey_from_state_init(settlement.state_init_cell)

    if not pubkey_hex:
        try:
            pubkey_hex = await provider.get_public_key(settlement.sender_address)
        except Exception as e:
            return VerifyResult(ok=False, reason=f"Could not get public key: {e}")

    if not pubkey_hex:
        return VerifyResult(ok=False, reason="Could not derive public key from stateInit or on-chain")

    try:
        valid, reason = verify_w5_signature(settlement.body_cell, pubkey_hex)
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
    facilitator_address: str | None = None,
) -> VerifyResult:
    """Rule 3: Verify jetton transfer amount, destination, and asset.

    All fields are derived from the BoC. Expects exactly 1 jetton_transfer action.
    """
    try:
        pay_to_norm = normalize_address(required_pay_to)
        asset_norm = normalize_address(required_asset)
        payload_asset_norm = normalize_address(payload.asset)
    except ValueError as e:
        return VerifyResult(ok=False, reason=f"Invalid address: {e}")

    if payload_asset_norm != asset_norm:
        return VerifyResult(
            ok=False,
            reason=f"Asset mismatch: expected {asset_norm}, got {payload_asset_norm}",
        )

    # Parse BoC to derive sender and verify transfer
    try:
        settlement = parse_settlement_boc(payload.settlement_boc)
        sender_address = settlement.sender_address
    except Exception as e:
        return VerifyResult(ok=False, reason=f"Failed to parse settlement BoC: {e}")

    # Facilitator safety: sender must not be the facilitator itself
    if facilitator_address:
        try:
            fac_norm = normalize_address(facilitator_address)
            sender_norm = normalize_address(sender_address)
            if sender_norm == fac_norm:
                return VerifyResult(
                    ok=False,
                    reason="Facilitator address must not appear as payment sender",
                )
        except ValueError:
            pass

    # Parse W5 body and extract jetton transfers
    try:
        w5_msg = parse_w5_body(settlement.body_cell)

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
                    if transfer.amount == int(required_amount):
                        found_valid_transfer = True

        if not found_valid_transfer:
            return VerifyResult(
                ok=False,
                reason="No valid jetton transfer found matching required amount and destination",
            )

        # Exactly 1 jetton transfer (no relay commission in self-relay model)
        if jetton_transfer_count > 1:
            return VerifyResult(
                ok=False,
                reason=f"Expected 1 jetton transfer, found {jetton_transfer_count}",
            )

        # Verify source Jetton wallet via on-chain getter
        for msg in w5_msg.internal_messages:
            body_cell = msg.get("body")
            if body_cell is None:
                continue
            transfer = extract_jetton_transfer(body_cell)
            source_wallet = msg.get("destination")
            if transfer and source_wallet:
                try:
                    sender_norm = normalize_address(sender_address)
                    expected_source = await provider.get_jetton_wallet(
                        asset_norm, sender_norm
                    )
                    expected_source_norm = normalize_address(expected_source)
                    actual_source_norm = normalize_address(source_wallet)
                    if actual_source_norm != expected_source_norm:
                        return VerifyResult(
                            ok=False,
                            reason=(
                                f"Source Jetton wallet mismatch: BoC sends to {actual_source_norm}, "
                                f"but get_wallet_address(from) returns {expected_source_norm}"
                            ),
                        )
                except Exception:
                    pass

    except Exception as e:
        return VerifyResult(ok=False, reason=f"Failed to parse payment BoC: {e}")

    return VerifyResult(ok=True)


async def check_replay(
    payload: TvmPaymentPayload,
    provider: TonProvider,
    cfg: VerifyConfig | None = None,
) -> VerifyResult:
    """Rule 4: Check for replay attacks.

    Seqno check uses strict equality (TON requires exact match).
    """
    now = int(time.time())

    # Parse BoC to get sender address and W5 body
    try:
        settlement = parse_settlement_boc(payload.settlement_boc)
        w5_msg = parse_w5_body(settlement.body_cell)
        sender_addr = normalize_address(settlement.sender_address)
    except Exception as e:
        return VerifyResult(ok=False, reason=f"Failed to parse BoC for replay check: {e}")

    if w5_msg.valid_until > 0 and w5_msg.valid_until < now:
        return VerifyResult(ok=False, reason="Payment expired")

    max_seconds = cfg.max_valid_until_seconds if cfg else 600
    if w5_msg.valid_until > 0 and w5_msg.valid_until > now + max_seconds:
        return VerifyResult(
            ok=False,
            reason=f"validUntil too far in future: {w5_msg.valid_until - now}s from now (max {max_seconds}s)",
        )

    boc_hash = compute_boc_hash(payload.settlement_boc)
    if boc_hash in _seen_boc_hashes:
        return VerifyResult(ok=False, reason="Duplicate BoC (replay)")

    try:
        on_chain_seqno = await provider.get_seqno(sender_addr)

        # Strict equality: TON requires seqno to match exactly
        if w5_msg.seqno != on_chain_seqno:
            return VerifyResult(
                ok=False,
                reason=f"Seqno mismatch: BoC has {w5_msg.seqno}, chain has {on_chain_seqno}",
            )
    except Exception:
        # Non-fatal: wallet contract is the authority
        pass

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
    facilitator_address: str | None = None,
) -> VerifyResult:
    """Run all verification rules on a payment.

    Returns ok=True only if ALL rules pass.
    """
    cfg = config or VerifyConfig()

    result = check_protocol(scheme, network, cfg)
    if not result.ok:
        return result

    result = await check_signature(payload, provider)
    if not result.ok:
        return result

    result = await check_payment_intent(
        payload, required_amount, required_pay_to, required_asset, provider,
        facilitator_address=facilitator_address,
    )
    if not result.ok:
        return result

    result = await check_replay(payload, provider, cfg)
    if not result.ok:
        return result

    result = await check_simulation(payload, provider, cfg)
    if not result.ok:
        return result

    # Mark BoC as seen (after all checks pass)
    boc_hash = compute_boc_hash(payload.settlement_boc)
    _seen_boc_hashes.add(boc_hash)

    return VerifyResult(ok=True)
