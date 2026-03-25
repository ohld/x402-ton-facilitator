"""Tests for self-relay architecture with internal message BoC format.

Tests the full pipeline:
1. Sign W5 transfer (facilitator's signing.py produces external BoC for itself)
2. Build internal message BoC (simulating what SDK client produces)
3. Parse settlement BoC (internal message format)
4. Verify signature (pubkey from stateInit)
5. Extract jetton transfer details
"""

import base64

import pytest
from nacl.signing import SigningKey
from pytoniq_core import Address, Builder, Cell

from tvm_core.boc import (
    extract_pubkey_from_state_init,
    parse_boc_and_extract,
    parse_settlement_boc,
    parse_w5_body,
)
from tvm_core.constants import INTERNAL_SIGNED_OP, JETTON_TRANSFER_OP
from tvm_core.ed25519 import verify_w5_signature
from tvm_core.jetton import build_jetton_transfer_payload
from tvm_core.signing import W5R1Signer


@pytest.fixture
def signer(test_keypair):
    return W5R1Signer(bytes(test_keypair), wallet_id=-239)


def build_internal_message_boc(
    dest_address: str,
    body_cell: Cell,
    state_init_cell: Cell | None = None,
    bounce: bool = True,
) -> str:
    """Build an internal message BoC (simulates what the SDK client produces).

    This is the new settlementBoc format: an internal message containing
    the signed W5 body and optional stateInit.
    """
    b = Builder()
    b.store_bit(0)  # int_msg_info$0
    b.store_bit(1)  # ihr_disabled
    b.store_bit(1 if bounce else 0)  # bounce
    b.store_bit(0)  # bounced
    b.store_uint(0, 2)  # src: addr_none$00
    b.store_address(Address(dest_address))
    b.store_coins(0)  # value (placeholder)
    b.store_bit(0)  # no extra_currencies
    b.store_coins(0)  # ihr_fee
    b.store_coins(0)  # fwd_fee
    b.store_uint(0, 64)  # created_lt
    b.store_uint(0, 32)  # created_at

    if state_init_cell:
        b.store_bit(1)  # has state_init
        b.store_bit(1)  # as ref
        b.store_ref(state_init_cell)
    else:
        b.store_bit(0)  # no state_init

    b.store_bit(1)  # body as ref
    b.store_ref(body_cell)

    return base64.b64encode(b.end_cell().to_boc()).decode()


class TestInternalMessageBocFormat:
    def test_parse_settlement_boc(self, signer):
        """Settlement BoC (internal message) is parsed correctly."""
        msgs = [{"address": "0:" + "aa" * 32, "amount": "100000000"}]
        # Sign a W5 transfer to get the body cell
        ext_boc = signer.sign_transfer(
            seqno=1, valid_until=1999999999, messages=msgs, auth_type="internal"
        )
        # Extract body from the external message (what the signer produces)
        from tvm_core.boc import _load_msg_address
        raw = base64.b64decode(ext_boc)
        cell = Cell.one_from_boc(raw)
        cs = cell.begin_parse()
        cs.load_uint(2)  # ext tag
        cs.load_uint(2)  # src addr_none
        cs.load_address()  # dest
        cs.load_coins()  # import_fee
        cs.load_bit()  # no state_init
        cs.load_bit()  # body as ref
        body_cell = cs.load_ref()

        # Wrap in internal message (new format)
        settlement_boc = build_internal_message_boc(signer.address, body_cell)

        # Parse it
        settlement = parse_settlement_boc(settlement_boc)
        assert settlement.sender_address == signer.address
        assert settlement.body_cell is not None
        assert settlement.state_init_cell is None

    def test_parse_settlement_boc_with_state_init(self, signer):
        """Settlement BoC with stateInit (seqno=0) is parsed correctly."""
        msgs = [{"address": "0:" + "aa" * 32, "amount": "100000000"}]
        ext_boc = signer.sign_transfer(
            seqno=0, valid_until=1999999999, messages=msgs, auth_type="internal"
        )
        # Extract body and stateInit from external message
        raw = base64.b64decode(ext_boc)
        cell = Cell.one_from_boc(raw)
        cs = cell.begin_parse()
        cs.load_uint(2)  # ext tag
        cs.load_uint(2)  # src addr_none
        cs.load_address()  # dest
        cs.load_coins()  # import_fee
        has_si = cs.load_bit()
        assert has_si
        cs.load_bit()  # as ref
        state_init_cell = cs.load_ref()
        cs.load_bit()  # body as ref
        body_cell = cs.load_ref()

        # Wrap in internal message with stateInit
        settlement_boc = build_internal_message_boc(
            signer.address, body_cell, state_init_cell=state_init_cell
        )

        settlement = parse_settlement_boc(settlement_boc)
        assert settlement.sender_address == signer.address
        assert settlement.body_cell is not None
        assert settlement.state_init_cell is not None

    def test_extract_pubkey_from_state_init(self, signer):
        """Public key can be extracted from stateInit."""
        msgs = [{"address": "0:" + "aa" * 32, "amount": "100000000"}]
        ext_boc = signer.sign_transfer(
            seqno=0, valid_until=1999999999, messages=msgs, auth_type="internal"
        )
        raw = base64.b64decode(ext_boc)
        cell = Cell.one_from_boc(raw)
        cs = cell.begin_parse()
        cs.load_uint(2)
        cs.load_uint(2)
        cs.load_address()
        cs.load_coins()
        cs.load_bit()  # has_si
        cs.load_bit()  # as ref
        state_init_cell = cs.load_ref()

        pubkey = extract_pubkey_from_state_init(state_init_cell)
        assert pubkey is not None
        assert pubkey == signer.public_key

    def test_signature_verification_from_internal_boc(self, signer):
        """Ed25519 signature verifies correctly from internal message BoC body."""
        msgs = [{"address": "0:" + "aa" * 32, "amount": "100000000"}]
        ext_boc = signer.sign_transfer(
            seqno=1, valid_until=1999999999, messages=msgs, auth_type="internal"
        )
        # Extract body cell
        raw = base64.b64decode(ext_boc)
        cell = Cell.one_from_boc(raw)
        cs = cell.begin_parse()
        cs.load_uint(2)
        cs.load_uint(2)
        cs.load_address()
        cs.load_coins()
        cs.load_bit()
        cs.load_bit()
        body_cell = cs.load_ref()

        # Verify with body cell directly (new API)
        ok, reason = verify_w5_signature(body_cell, signer.public_key)
        assert ok, f"Signature verification failed: {reason}"

    def test_wrong_key_fails(self, signer):
        """Signature fails with wrong public key."""
        msgs = [{"address": "0:" + "aa" * 32, "amount": "100000000"}]
        ext_boc = signer.sign_transfer(
            seqno=1, valid_until=1999999999, messages=msgs, auth_type="internal"
        )
        raw = base64.b64decode(ext_boc)
        cell = Cell.one_from_boc(raw)
        cs = cell.begin_parse()
        cs.load_uint(2)
        cs.load_uint(2)
        cs.load_address()
        cs.load_coins()
        cs.load_bit()
        cs.load_bit()
        body_cell = cs.load_ref()

        wrong_key = SigningKey.generate()
        ok, reason = verify_w5_signature(body_cell, bytes(wrong_key.verify_key).hex())
        assert not ok


class TestJettonPayloadWithInternalBoc:
    def test_full_pipeline(self, signer):
        """Full pipeline: build jetton payload -> sign -> wrap in internal msg -> parse -> extract."""
        dest = "0:" + "bb" * 32
        payload_boc = build_jetton_transfer_payload(destination=dest, amount=50000)

        msgs = [{
            "address": "0:" + "cc" * 32,  # jetton wallet address
            "amount": "50000000",
            "payload": payload_boc,
        }]

        # Sign transfer (produces external message)
        ext_boc = signer.sign_transfer(
            seqno=10, valid_until=2000000000, messages=msgs, auth_type="internal"
        )

        # Extract body from external message
        raw = base64.b64decode(ext_boc)
        cell = Cell.one_from_boc(raw)
        cs = cell.begin_parse()
        cs.load_uint(2)
        cs.load_uint(2)
        cs.load_address()
        cs.load_coins()
        cs.load_bit()
        cs.load_bit()
        body_cell = cs.load_ref()

        # Build settlement BoC (internal message format)
        settlement_boc = build_internal_message_boc(signer.address, body_cell)

        # Parse and extract (new API returns 3 values)
        settlement, w5_msg, jetton_transfers = parse_boc_and_extract(settlement_boc)
        assert settlement.sender_address == signer.address
        assert w5_msg.seqno == 10
        assert len(w5_msg.internal_messages) == 1
        assert len(jetton_transfers) == 1
        assert jetton_transfers[0].amount == 50000
        assert jetton_transfers[0].destination == dest

    def test_w5_body_parsing(self, signer):
        """W5 body is parsed correctly from internal message BoC."""
        msgs = [{"address": "0:" + "aa" * 32, "amount": "100000000"}]
        ext_boc = signer.sign_transfer(
            seqno=42, valid_until=1888888888, messages=msgs, auth_type="internal"
        )

        # Extract body from external message
        raw = base64.b64decode(ext_boc)
        cell = Cell.one_from_boc(raw)
        cs = cell.begin_parse()
        cs.load_uint(2)
        cs.load_uint(2)
        cs.load_address()
        cs.load_coins()
        cs.load_bit()
        cs.load_bit()
        body_cell = cs.load_ref()

        w5_msg = parse_w5_body(body_cell)
        assert w5_msg.seqno == 42
        assert w5_msg.valid_until == 1888888888
        assert len(w5_msg.internal_messages) == 1
