"""Ed25519 signature verification for W5 (Wallet v5r1) wallets."""

from __future__ import annotations

import base64

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from pytoniq_core import Cell

from tvm_core.boc import parse_external_message
from tvm_core.constants import INTERNAL_SIGNED_OP, EXTERNAL_SIGNED_OP, W5R1_CODE_HASH


def verify_w5_signature(boc_b64: str, pubkey_hex: str) -> tuple[bool, str]:
    """Verify the Ed25519 signature of a W5R1 external message.

    W5R1 body layout: [optional opcode] [512-bit signature] [signed payload].
    The signature covers the hash of the payload cell.

    Args:
        boc_b64: Base64-encoded BoC containing the external message.
        pubkey_hex: Hex-encoded Ed25519 public key of the wallet owner.

    Returns:
        (True, "") on success, (False, reason) on failure.
    """
    try:
        body = parse_external_message(boc_b64)
    except Exception as e:
        return False, f"Failed to parse BoC: {e}"

    body_slice = body.begin_parse()

    # V5R1 body layout: [signing_message_data...] [signature(512 bits at tail)]
    # The signature is always the LAST 512 bits of the body cell.
    total_bits = body_slice.remaining_bits
    if total_bits < 512:
        return False, f"Body too short for signature: {total_bits} bits"

    signed_data_bits = total_bits - 512  # everything before the signature
    refs_count = body_slice.remaining_refs

    # Reconstruct the signing message cell (data before signature + all refs)
    from pytoniq_core import Builder
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
    state_init_boc_b64: str,
    allowed_hashes: set[str] | None = None,
) -> bool:
    """Verify that a StateInit contains the expected W5R1 contract code.

    Args:
        state_init_boc_b64: Base64-encoded BoC of the StateInit.
        allowed_hashes: Optional set of allowed code hashes (base64).
                        Defaults to {W5R1_CODE_HASH}.

    Returns:
        True if the code cell hash matches an allowed hash.
    """
    if allowed_hashes is None:
        allowed_hashes = {W5R1_CODE_HASH}

    try:
        cell = Cell.one_from_boc(base64.b64decode(state_init_boc_b64))
    except Exception:
        return False

    # StateInit TL-B: _ split_depth:(Maybe (## 5)) special:(Maybe TickTock)
    #   code:(Maybe ^Cell) data:(Maybe ^Cell) library:(HashmapE 256 SimpleLib) = StateInit;
    si_slice = cell.begin_parse()

    # split_depth: Maybe (## 5) — 1 bit flag, if 1 then 5 bits value
    if si_slice.load_bit():
        si_slice.skip_bits(5)

    # special: Maybe TickTock — 1 bit flag, if 1 then 2 bits value
    if si_slice.load_bit():
        si_slice.skip_bits(2)

    # code: Maybe ^Cell — 1 bit flag, if 1 then a ref
    has_code = si_slice.load_bit()
    if not has_code:
        return False

    code_cell = si_slice.load_ref()
    code_hash_b64 = base64.b64encode(code_cell.hash).decode()

    return code_hash_b64 in allowed_hashes
