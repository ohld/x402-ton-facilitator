"""Tests for W5R1 signing — roundtrip with existing verification and parsing."""

import base64

import pytest
from nacl.signing import SigningKey
from pytoniq_core import Builder, Cell

from tvm_core.boc import parse_external_message, parse_w5_body
from tvm_core.constants import W5R1_CODE_HASH
from tvm_core.ed25519 import verify_w5_code_hash, verify_w5_signature
from tvm_core.signing import W5R1Signer, create_w5_sign_fn


@pytest.fixture
def signer(test_keypair):
    return W5R1Signer(bytes(test_keypair), wallet_id=-239)


@pytest.fixture
def dummy_messages():
    """Two simple TON transfer messages (no jetton payload)."""
    return [
        {"address": "0:" + "aa" * 32, "amount": "100000000"},
        {"address": "0:" + "bb" * 32, "amount": "200000000"},
    ]


def _extract_body(boc_b64: str) -> Cell:
    """Extract body cell from a signed external message BoC."""
    return parse_external_message(boc_b64)


class TestW5R1Signer:
    def test_address_format(self, signer):
        addr = signer.address
        assert ":" in addr
        wc, hash_hex = addr.split(":")
        assert wc == "0"
        assert len(hash_hex) == 64
        bytes.fromhex(hash_hex)

    def test_public_key_hex(self, signer, test_keypair):
        assert signer.public_key == bytes(test_keypair.verify_key).hex()
        assert len(signer.public_key) == 64

    def test_sign_verify_roundtrip(self, signer, dummy_messages):
        boc_b64 = signer.sign_transfer(
            seqno=1, valid_until=1999999999, messages=dummy_messages
        )
        body = _extract_body(boc_b64)
        ok, reason = verify_w5_signature(body, signer.public_key)
        assert ok, f"Signature verification failed: {reason}"

    def test_parsed_fields_match(self, signer, dummy_messages):
        seqno = 42
        valid_until = 1888888888
        boc_b64 = signer.sign_transfer(
            seqno=seqno, valid_until=valid_until, messages=dummy_messages
        )
        body = _extract_body(boc_b64)
        w5_msg = parse_w5_body(body)

        assert w5_msg.seqno == seqno
        assert w5_msg.valid_until == valid_until
        assert len(w5_msg.internal_messages) == 2
        assert w5_msg.internal_messages[0]["destination"] == "0:" + "aa" * 32
        assert w5_msg.internal_messages[0]["amount"] == 100000000
        assert w5_msg.internal_messages[1]["destination"] == "0:" + "bb" * 32
        assert w5_msg.internal_messages[1]["amount"] == 200000000

    def test_single_message(self, signer):
        msgs = [{"address": "0:" + "cc" * 32, "amount": "50000000"}]
        boc_b64 = signer.sign_transfer(seqno=1, valid_until=1999999999, messages=msgs)
        body = _extract_body(boc_b64)
        ok, _ = verify_w5_signature(body, signer.public_key)
        assert ok

        w5_msg = parse_w5_body(body)
        assert len(w5_msg.internal_messages) == 1

    def test_seqno_zero_includes_state_init(self, signer, dummy_messages):
        boc_b64 = signer.sign_transfer(
            seqno=0, valid_until=1999999999, messages=dummy_messages
        )
        raw = base64.b64decode(boc_b64)
        cell = Cell.one_from_boc(raw)
        cs = cell.begin_parse()

        assert cs.load_uint(2) == 2
        cs.load_uint(2)
        cs.load_address()
        cs.load_coins()

        has_si = cs.load_bit()
        assert has_si, "seqno=0 should include state_init"
        is_ref = cs.load_bit()
        assert is_ref
        si_cell = cs.load_ref()

        assert verify_w5_code_hash(si_cell)

    def test_seqno_nonzero_no_state_init(self, signer, dummy_messages):
        boc_b64 = signer.sign_transfer(
            seqno=5, valid_until=1999999999, messages=dummy_messages
        )
        raw = base64.b64decode(boc_b64)
        cell = Cell.one_from_boc(raw)
        cs = cell.begin_parse()

        cs.load_uint(2)
        cs.load_uint(2)
        cs.load_address()
        cs.load_coins()

        has_si = cs.load_bit()
        assert not has_si, "seqno>0 should not include state_init"

    def test_code_hash_matches_constant(self, signer):
        from tvm_core.signing import _load_w5r1_code

        code_cell = _load_w5r1_code()
        code_hash_b64 = base64.b64encode(code_cell.hash).decode()
        assert code_hash_b64 == W5R1_CODE_HASH

    def test_wrong_key_fails_verification(self, signer, dummy_messages):
        boc_b64 = signer.sign_transfer(
            seqno=1, valid_until=1999999999, messages=dummy_messages
        )
        body = _extract_body(boc_b64)
        wrong_key = SigningKey.generate()
        wrong_pubkey = bytes(wrong_key.verify_key).hex()
        ok, reason = verify_w5_signature(body, wrong_pubkey)
        assert not ok
        assert "failed" in reason.lower() or "error" in reason.lower()

    def test_message_with_payload(self, signer):
        pb = Builder()
        pb.store_uint(0x0F8A7EA5, 32)
        pb.store_uint(0, 64)
        pb.store_coins(1000000)
        pb.store_uint(0, 2)
        pb.store_uint(0, 2)
        pb.store_bit(0)
        pb.store_coins(1)
        pb.store_bit(0)
        payload_boc = base64.b64encode(pb.end_cell().to_boc()).decode()

        msgs = [
            {"address": "0:" + "dd" * 32, "amount": "50000000", "payload": payload_boc}
        ]
        boc_b64 = signer.sign_transfer(seqno=1, valid_until=1999999999, messages=msgs)

        body = _extract_body(boc_b64)
        ok, _ = verify_w5_signature(body, signer.public_key)
        assert ok

        w5_msg = parse_w5_body(body)
        assert len(w5_msg.internal_messages) == 1
        body_cell = w5_msg.internal_messages[0]["body"]
        cs = body_cell.begin_parse()
        assert cs.load_uint(32) == 0x0F8A7EA5

    def test_empty_messages(self, signer):
        boc_b64 = signer.sign_transfer(seqno=1, valid_until=1999999999, messages=[])
        body = _extract_body(boc_b64)
        ok, _ = verify_w5_signature(body, signer.public_key)
        assert ok

        w5_msg = parse_w5_body(body)
        assert w5_msg.seqno == 1
        assert len(w5_msg.internal_messages) == 0

    def test_deterministic_address(self, test_keypair):
        s1 = W5R1Signer(bytes(test_keypair), wallet_id=-239)
        s2 = W5R1Signer(bytes(test_keypair), wallet_id=-239)
        assert s1.address == s2.address

    def test_different_wallet_id_different_address(self, test_keypair):
        s1 = W5R1Signer(bytes(test_keypair), wallet_id=-239)
        s2 = W5R1Signer(bytes(test_keypair), wallet_id=-3)
        assert s1.address != s2.address


class TestCreateW5SignFn:
    @pytest.mark.asyncio
    async def test_sign_fn_returns_valid_boc(self, test_keypair):
        sign_fn = create_w5_sign_fn(bytes(test_keypair))
        msgs = [{"address": "0:" + "aa" * 32, "amount": "100000000"}]
        boc_b64 = await sign_fn(seqno=1, valid_until=1999999999, messages=msgs)

        signer = W5R1Signer(bytes(test_keypair))
        body = _extract_body(boc_b64)
        ok, _ = verify_w5_signature(body, signer.public_key)
        assert ok

    @pytest.mark.asyncio
    async def test_sign_fn_address_matches_signer(self, test_keypair):
        sign_fn = create_w5_sign_fn(bytes(test_keypair))
        signer = W5R1Signer(bytes(test_keypair))

        msgs = [{"address": "0:" + "aa" * 32, "amount": "100000000"}]
        boc_b64 = await sign_fn(seqno=1, valid_until=1999999999, messages=msgs)

        body = _extract_body(boc_b64)
        ok, _ = verify_w5_signature(body, signer.public_key)
        assert ok
