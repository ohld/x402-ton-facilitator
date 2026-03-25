"""Ed25519 signature verification for W5 (Wallet v5r1) wallets.

The public key is derived from:
- stateInit data cell (seqno == 0, wallet deployment)
- On-chain get_public_key getter (seqno > 0)

No walletPublicKey field in the payload — derived from BoC or on-chain.
"""

from __future__ import annotations

import base64

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from pytoniq_core import Builder, Cell

from tvm_core.constants import W5R1_CODE_HASH


def verify_w5_signature(body_cell: Cell, pubkey_hex: str) -> tuple[bool, str]:
    """Verify the Ed25519 signature of a W5R1 message body.

    W5R1 body layout: [signed_data...] [signature(512 bits at tail)]
    The signature covers the hash of everything before it (+ refs).

    Args:
        body_cell: The W5 signed body cell (extracted from settlement BoC).
        pubkey_hex: Hex-encoded Ed25519 public key.

    Returns:
        (True, "") on success, (False, reason) on failure.
    """
    body_slice = body_cell.begin_parse()

    total_bits = body_slice.remaining_bits
    if total_bits < 512:
        return False, f"Body too short for signature: {total_bits} bits"

    signed_data_bits = total_bits - 512
    refs_count = body_slice.remaining_refs

    # Reconstruct the signing message cell (data before signature + all refs)
    builder = Builder()
    if signed_data_bits > 0:
        builder.store_bits(body_slice.load_bits(signed_data_bits))
    for _ in range(refs_count):
        builder.store_ref(body_slice.load_ref())
    signed_cell = builder.end_cell()
    signed_data = signed_cell.hash

    # Read signature from the remaining 512 bits
    signature = body_slice.load_bytes(64)

    try:
        verify_key = VerifyKey(bytes.fromhex(pubkey_hex))
    except Exception as e:
        return False, f"Invalid public key: {e}"

    try:
        verify_key.verify(signed_data, signature)
    except BadSignatureError:
        return False, "Ed25519 signature verification failed"
    except Exception as e:
        return False, f"Signature verification error: {e}"

    return True, ""


def verify_w5_code_hash(
    state_init_cell: Cell,
    allowed_hashes: set[str] | None = None,
) -> bool:
    """Verify that a StateInit contains the expected W5R1 contract code.

    Args:
        state_init_cell: The stateInit cell (already parsed, not base64).
        allowed_hashes: Optional set of allowed code hashes (base64).
                        Defaults to {W5R1_CODE_HASH}.

    Returns:
        True if the code cell hash matches an allowed hash.
    """
    if allowed_hashes is None:
        allowed_hashes = {W5R1_CODE_HASH}

    try:
        si_slice = state_init_cell.begin_parse()

        # split_depth: Maybe (## 5)
        if si_slice.load_bit():
            si_slice.skip_bits(5)

        # special: Maybe TickTock
        if si_slice.load_bit():
            si_slice.skip_bits(2)

        # code: Maybe ^Cell
        has_code = si_slice.load_bit()
        if not has_code:
            return False

        code_cell = si_slice.load_ref()
        code_hash_b64 = base64.b64encode(code_cell.hash).decode()

        return code_hash_b64 in allowed_hashes
    except Exception:
        return False
