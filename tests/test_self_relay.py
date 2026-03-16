"""Tests for self-relay architecture: internal_signed format and jetton payload."""

import base64

import pytest
from nacl.signing import SigningKey
from pytoniq_core import Builder, Cell

from tvm_core.boc import parse_boc_and_extract, parse_external_message, parse_w5_body
from tvm_core.constants import INTERNAL_SIGNED_OP, JETTON_TRANSFER_OP
from tvm_core.ed25519 import verify_w5_signature
from tvm_core.jetton import build_jetton_transfer_payload
from tvm_core.signing import W5R1Signer


@pytest.fixture
def signer(test_keypair):
    return W5R1Signer(bytes(test_keypair), wallet_id=-239)


class TestInternalSignedFormat:
    def test_internal_signed_verify(self, signer):
        """BoC with auth_type='internal' passes signature verification."""
        msgs = [{"address": "0:" + "aa" * 32, "amount": "100000000"}]
        boc = signer.sign_transfer(seqno=1, valid_until=1999999999, messages=msgs, auth_type="internal")

        ok, reason = verify_w5_signature(boc, signer.public_key)
        assert ok, f"internal_signed verification failed: {reason}"

    def test_internal_signed_parse(self, signer):
        """BoC with internal_signed opcode is parsed correctly."""
        msgs = [{"address": "0:" + "aa" * 32, "amount": "100000000"}]
        boc = signer.sign_transfer(seqno=42, valid_until=1888888888, messages=msgs, auth_type="internal")

        body = parse_external_message(boc)
        w5_msg = parse_w5_body(body)
        assert w5_msg.seqno == 42
        assert w5_msg.valid_until == 1888888888
        assert len(w5_msg.internal_messages) == 1

    def test_internal_signed_has_opcode(self, signer):
        """The body cell starts with 0x73696e74 opcode."""
        msgs = [{"address": "0:" + "aa" * 32, "amount": "100000000"}]
        boc = signer.sign_transfer(seqno=1, valid_until=1999999999, messages=msgs, auth_type="internal")

        body = parse_external_message(boc)
        cs = body.begin_parse()
        opcode = cs.load_uint(32)
        assert opcode == INTERNAL_SIGNED_OP

    def test_external_signed_no_opcode(self, signer):
        """Standard external format has no opcode prefix."""
        msgs = [{"address": "0:" + "aa" * 32, "amount": "100000000"}]
        boc = signer.sign_transfer(seqno=1, valid_until=1999999999, messages=msgs, auth_type="external")

        body = parse_external_message(boc)
        cs = body.begin_parse()
        # First 32 bits should NOT be a known opcode (it's part of the signature)
        first_32 = cs.preload_uint(32)
        assert first_32 != INTERNAL_SIGNED_OP

    def test_both_formats_same_data(self, signer):
        """External and internal formats parse to the same seqno/validUntil/messages."""
        msgs = [{"address": "0:" + "aa" * 32, "amount": "100000000"}]
        ext_boc = signer.sign_transfer(seqno=5, valid_until=2000000000, messages=msgs, auth_type="external")
        int_boc = signer.sign_transfer(seqno=5, valid_until=2000000000, messages=msgs, auth_type="internal")

        ext_body = parse_external_message(ext_boc)
        int_body = parse_external_message(int_boc)

        ext_parsed = parse_w5_body(ext_body)
        int_parsed = parse_w5_body(int_body)

        assert ext_parsed.seqno == int_parsed.seqno == 5
        assert ext_parsed.valid_until == int_parsed.valid_until == 2000000000
        assert len(ext_parsed.internal_messages) == len(int_parsed.internal_messages) == 1

    def test_wrong_key_fails_internal(self, signer):
        """Internal_signed BoC signed with one key fails with another."""
        msgs = [{"address": "0:" + "aa" * 32, "amount": "100000000"}]
        boc = signer.sign_transfer(seqno=1, valid_until=1999999999, messages=msgs, auth_type="internal")

        wrong_key = SigningKey.generate()
        ok, reason = verify_w5_signature(boc, bytes(wrong_key.verify_key).hex())
        assert not ok


class TestJettonPayload:
    def test_build_jetton_transfer(self):
        """Built payload is a valid TEP-74 jetton_transfer cell."""
        dest = "0:" + "aa" * 32
        payload_b64 = build_jetton_transfer_payload(destination=dest, amount=10000)

        cell = Cell.one_from_boc(base64.b64decode(payload_b64))
        cs = cell.begin_parse()
        assert cs.load_uint(32) == JETTON_TRANSFER_OP
        cs.load_uint(64)  # query_id
        amount = cs.load_coins()
        assert amount == 10000

    def test_internal_signed_with_jetton_payload(self, signer):
        """Full pipeline: build jetton payload → sign internal → parse → extract."""
        dest = "0:" + "bb" * 32
        payload_boc = build_jetton_transfer_payload(destination=dest, amount=50000)

        msgs = [{
            "address": "0:" + "cc" * 32,  # jetton wallet address
            "amount": "50000000",
            "payload": payload_boc,
        }]
        boc = signer.sign_transfer(seqno=10, valid_until=2000000000, messages=msgs, auth_type="internal")

        # Verify signature
        ok, _ = verify_w5_signature(boc, signer.public_key)
        assert ok

        # Parse and extract
        w5_msg, jetton_transfers = parse_boc_and_extract(boc)
        assert w5_msg.seqno == 10
        assert len(w5_msg.internal_messages) == 1
        assert len(jetton_transfers) == 1
        assert jetton_transfers[0].amount == 50000
        assert jetton_transfers[0].destination == dest
