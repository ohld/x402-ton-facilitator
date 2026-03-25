"""BoC (Bag of Cells) parser for W5 wallet messages.

Parses settlement BoC (internal message format) and extracts:
- Sender wallet address (from dest field)
- W5 signed body (seqno, valid_until, actions)
- Jetton transfer details (destination, amount)
- Public key (from stateInit data cell)
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from pytoniq_core import Address, Cell

from .constants import INTERNAL_SIGNED_OP, EXTERNAL_SIGNED_OP, JETTON_TRANSFER_OP, MAX_BOC_SIZE
from .types import JettonTransferInfo, SettlementData, W5ParsedMessage


def parse_external_message(boc_b64: str) -> Cell:
    """Parse a base64 BoC containing an external message and return the body cell.

    Used for the facilitator's own signed external messages (not client settlement BoC).
    """
    raw = base64.b64decode(boc_b64)
    if len(raw) > MAX_BOC_SIZE:
        raise ValueError(f"BoC too large: {len(raw)} bytes (max {MAX_BOC_SIZE})")

    cell = Cell.one_from_boc(raw)
    cs = cell.begin_parse()

    tag = cs.load_uint(2)
    if tag != 2:
        raise ValueError(f"Not an external message: tag={tag}")

    src_tag = cs.load_uint(2)
    if src_tag != 0:
        cs.skip_bits(src_tag)

    cs.load_address()
    cs.load_coins()

    has_state_init = cs.load_bit()
    if has_state_init:
        is_ref = cs.load_bit()
        if is_ref:
            cs.load_ref()
        else:
            raise ValueError("Inline state_init not supported")

    body_is_ref = cs.load_bit()
    if body_is_ref:
        return cs.load_ref()
    else:
        return cs.to_cell()


def parse_settlement_boc(boc_b64: str) -> SettlementData:
    """Parse a settlement BoC (internal message format).

    The client encodes the signed W5 body inside an internal message:
    - dest = client's wallet address
    - body = W5 signed body (with Ed25519 signature)
    - stateInit = optional wallet deployment code (seqno == 0)

    Args:
        boc_b64: Base64-encoded BoC containing an internal message.

    Returns:
        SettlementData with sender_address, body_cell, and optional state_init_cell.

    Raises:
        ValueError: If BoC is too large, malformed, or not an internal message.
    """
    raw = base64.b64decode(boc_b64)
    if len(raw) > MAX_BOC_SIZE:
        raise ValueError(f"BoC too large: {len(raw)} bytes (max {MAX_BOC_SIZE})")

    cell = Cell.one_from_boc(raw)
    cs = cell.begin_parse()

    # Internal message TL-B: int_msg_info$0 ...
    tag = cs.load_bit()
    if tag:
        raise ValueError("Expected internal message (tag=0), got external/other")

    # ihr_disabled, bounce, bounced
    _ihr_disabled = cs.load_bit()
    _bounce = cs.load_bit()
    _bounced = cs.load_bit()

    # src: MsgAddressInt (addr_none in client-built message)
    _src = _load_msg_address(cs)

    # dest: MsgAddressInt — this is the client's wallet address
    dest = _load_msg_address(cs)
    if not dest:
        raise ValueError("Missing destination address in settlement BoC")

    # value: CurrencyCollection (Grams + ExtraCurrencyCollection)
    _value = cs.load_coins()
    has_extra_currency = cs.load_bit()
    if has_extra_currency:
        cs.load_ref()  # skip extra currencies dict

    # ihr_fee, fwd_fee
    cs.load_coins()
    cs.load_coins()
    # created_lt, created_at
    cs.load_uint(64)
    cs.load_uint(32)

    # StateInit (Maybe (Either StateInit ^StateInit))
    state_init_cell = None
    has_state_init = cs.load_bit()
    if has_state_init:
        is_ref = cs.load_bit()
        if is_ref:
            state_init_cell = cs.load_ref()
        else:
            raise ValueError("Inline stateInit not supported, use ref format")

    # Body: Either X ^X
    body_is_ref = cs.load_bit()
    if body_is_ref and cs.remaining_refs > 0:
        body_cell = cs.load_ref()
    else:
        body_cell = cs.to_cell()

    return SettlementData(
        sender_address=dest,
        body_cell=body_cell,
        state_init_cell=state_init_cell,
    )


def extract_pubkey_from_state_init(state_init_cell: Cell) -> str | None:
    """Extract Ed25519 public key from a W5R1 stateInit data cell.

    W5R1 data layout: signature_allowed(1 bit) | seqno(32) | walletId(32) | publicKey(256)

    Args:
        state_init_cell: The stateInit cell from a W5R1 wallet.

    Returns:
        Hex-encoded public key, or None if extraction fails.
    """
    try:
        si = state_init_cell.begin_parse()

        # split_depth: Maybe (## 5)
        if si.load_bit():
            si.skip_bits(5)

        # special: Maybe TickTock
        if si.load_bit():
            si.skip_bits(2)

        # code: Maybe ^Cell
        has_code = si.load_bit()
        if has_code:
            si.load_ref()  # skip code cell

        # data: Maybe ^Cell
        has_data = si.load_bit()
        if not has_data:
            return None

        data_cell = si.load_ref()
        ds = data_cell.begin_parse()

        # W5R1 data: signature_allowed(1) | seqno(32) | walletId(32) | publicKey(256)
        _sig_allowed = ds.load_bit()
        _seqno = ds.load_uint(32)
        _wallet_id = ds.load_int(32)
        pubkey_bytes = ds.load_bytes(32)

        return pubkey_bytes.hex()
    except Exception:
        return None


# Known opcodes for internal_signed across wallet types
KNOWN_INTERNAL_OPCODES = {
    INTERNAL_SIGNED_OP,   # 0x73696e74 — W5R1, W5Beta
    EXTERNAL_SIGNED_OP,   # 0x7369676e — W5R1, W5Beta (external)
    0x4A3CA895,           # Agentic wallet InternalSignedRequest
}


def parse_w5_body(body_cell: Cell) -> W5ParsedMessage:
    """Parse a wallet body cell into structured data.

    Supports multiple wallet formats by trying parsers in order:
    - V5R1: opcode(32) | walletId(32) | validUntil(32) | seqno(32) | maybeRef(actions) | has_extended(1) | sig(512)

    Args:
        body_cell: The body cell from a wallet message.

    Returns:
        W5ParsedMessage with seqno, valid_until, and internal messages.
    """
    body_hash = hashlib.sha256(body_cell.to_boc()).hexdigest()

    # Try V5R1 parser first (most common)
    try:
        result = _parse_v5r1_body(body_cell)
        if result is not None:
            return W5ParsedMessage(**result, raw_body_hash=body_hash)
    except Exception:
        pass

    # Fallback: generic parser
    try:
        result = _parse_generic_body(body_cell)
        if result is not None:
            return W5ParsedMessage(**result, raw_body_hash=body_hash)
    except Exception:
        pass

    return W5ParsedMessage(
        seqno=0,
        valid_until=0,
        internal_messages=[],
        raw_body_hash=body_hash,
    )


def _parse_v5r1_body(body_cell: Cell) -> dict[str, Any] | None:
    """Parse V5R1 body format."""
    cs = body_cell.begin_parse()

    if cs.remaining_bits < 32:
        return None

    first_32 = cs.preload_uint(32)
    if first_32 not in KNOWN_INTERNAL_OPCODES:
        return None
    cs.load_uint(32)  # consume opcode

    if cs.remaining_bits < 96:
        return None

    _wallet_id = cs.load_int(32)
    valid_until = cs.load_uint(32)
    seqno = cs.load_uint(32)

    internal_messages: list[dict[str, Any]] = []

    if cs.remaining_bits >= 2:
        has_basic_actions = cs.load_bit()
        if has_basic_actions and cs.remaining_refs > 0:
            action_cell = cs.load_ref()
            msgs = _parse_w5_actions(action_cell)
            internal_messages.extend(msgs)
        _has_extended = cs.load_bit()

    return {
        "seqno": seqno,
        "valid_until": valid_until,
        "internal_messages": internal_messages,
    }


def _parse_generic_body(body_cell: Cell) -> dict[str, Any] | None:
    """Generic fallback parser: extract actions from cell refs."""
    internal_messages: list[dict[str, Any]] = []

    for ref in body_cell.refs:
        try:
            msgs = _parse_w5_actions(ref)
            if msgs:
                internal_messages.extend(msgs)
        except Exception:
            pass

    if not internal_messages:
        return None

    return {
        "seqno": 0,
        "valid_until": 0,
        "internal_messages": internal_messages,
    }


def _parse_w5_actions(action_cell: Cell) -> list[dict[str, Any]]:
    """Parse W5 OutList from a cell.

    Each action_send_msg: op#0ec3c86d mode:(## 8) out_msg:^(MessageRelaxed)
    Layout: [ref:prev] [op(32)] [mode(8)] [ref:msg]
    """
    SEND_MSG_OP = 0x0EC3C86D
    messages: list[dict[str, Any]] = []
    current = action_cell

    while True:
        cs = current.begin_parse()

        if cs.remaining_bits < 32:
            break

        if cs.remaining_refs < 1:
            break
        prev_cell = cs.load_ref()

        op = cs.load_uint(32)
        if op == SEND_MSG_OP and cs.remaining_refs > 0:
            mode = cs.load_uint(8)
            msg_cell = cs.load_ref()
            parsed = _parse_action_internal_message(msg_cell)
            parsed["send_mode"] = mode
            messages.append(parsed)

        if prev_cell.begin_parse().remaining_bits == 0 and len(prev_cell.refs) == 0:
            break
        current = prev_cell

    return messages


def _parse_action_internal_message(msg_cell: Cell) -> dict[str, Any]:
    """Parse an internal message cell from a W5 action."""
    cs = msg_cell.begin_parse()

    tag = cs.load_bit()
    if tag:
        raise ValueError("Expected internal message (tag=0), got external")

    cs.load_bit()  # ihr_disabled
    cs.load_bit()  # bounce
    cs.load_bit()  # bounced
    src = _load_msg_address(cs)
    dest = _load_msg_address(cs)
    amount = cs.load_coins()
    has_extra = cs.load_bit()
    if has_extra:
        cs.load_ref()

    cs.load_coins()  # ihr_fee
    cs.load_coins()  # fwd_fee
    cs.load_uint(64)  # created_lt
    cs.load_uint(32)  # created_at

    has_state_init = cs.load_bit()
    if has_state_init:
        is_ref = cs.load_bit()
        if is_ref:
            cs.load_ref()

    body_is_ref = cs.load_bit()
    if body_is_ref and cs.remaining_refs > 0:
        body_cell = cs.load_ref()
    else:
        body_cell = cs.to_cell()

    result: dict[str, Any] = {
        "destination": dest,
        "amount": amount,
        "body": body_cell,
    }
    if src:
        result["source"] = src

    return result


def _load_msg_address(cs) -> str | None:
    """Load a MsgAddress from a cell slice."""
    tag = cs.load_uint(2)
    if tag == 0:  # addr_none
        return None
    elif tag == 2:  # addr_std
        maybe_anycast = cs.load_bit()
        if maybe_anycast:
            depth = cs.load_uint(5)
            cs.skip_bits(depth)
        workchain = cs.load_int(8)
        hash_part = cs.load_bytes(32)
        return f"{workchain}:{hash_part.hex()}"
    elif tag == 3:  # addr_var
        maybe_anycast = cs.load_bit()
        if maybe_anycast:
            depth = cs.load_uint(5)
            cs.skip_bits(depth)
        addr_len = cs.load_uint(9)
        workchain = cs.load_int(32)
        addr_bytes = cs.load_bits(addr_len)
        return f"{workchain}:{addr_bytes.hex()}"
    else:
        addr_len = cs.load_uint(9)
        cs.skip_bits(addr_len)
        return None


def extract_jetton_transfer(body_cell: Cell) -> JettonTransferInfo | None:
    """Extract jetton transfer details from an internal message body.

    TEP-74 jetton_transfer body:
    - uint32: op = 0x0f8a7ea5
    - uint64: query_id
    - coins: amount
    - address: destination
    - address: response_destination
    - Maybe ^Cell: custom_payload
    - coins: forward_ton_amount
    - Maybe ^Cell: forward_payload
    """
    cs = body_cell.begin_parse()

    if cs.remaining_bits < 32:
        return None

    op = cs.load_uint(32)
    if op != JETTON_TRANSFER_OP:
        return None

    _query_id = cs.load_uint(64)
    amount = cs.load_coins()
    destination = _load_msg_address(cs)
    response_dest = _load_msg_address(cs)

    has_custom = cs.load_bit()
    if has_custom:
        cs.load_ref()

    forward_ton = cs.load_coins()

    return JettonTransferInfo(
        destination=destination or "",
        amount=int(amount),
        response_destination=response_dest,
        forward_ton_amount=int(forward_ton),
    )


def parse_boc_and_extract(boc_b64: str) -> tuple[SettlementData, W5ParsedMessage, list[JettonTransferInfo]]:
    """Full pipeline: parse settlement BoC -> extract W5 message -> find jetton transfers.

    Args:
        boc_b64: Base64-encoded settlement BoC (internal message format).

    Returns:
        Tuple of (SettlementData, W5ParsedMessage, list of JettonTransferInfo).
    """
    settlement = parse_settlement_boc(boc_b64)
    w5_msg = parse_w5_body(settlement.body_cell)

    jetton_transfers: list[JettonTransferInfo] = []
    for msg in w5_msg.internal_messages:
        body_cell = msg.get("body")
        if body_cell is None:
            continue
        info = extract_jetton_transfer(body_cell)
        if info:
            info.jetton_wallet = msg.get("destination", "")
            jetton_transfers.append(info)

    return settlement, w5_msg, jetton_transfers


def compute_boc_hash(boc_b64: str) -> str:
    """Compute a stable hash of a BoC for deduplication."""
    raw = base64.b64decode(boc_b64)
    return hashlib.sha256(raw).hexdigest()
