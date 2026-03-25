"""End-to-end tests for the signing -> verification pipeline."""

import base64
import os
import time

import pytest
from nacl.signing import SigningKey
from pytoniq_core import Cell

from tvm_core.boc import parse_external_message, parse_w5_body
from tvm_core.ed25519 import verify_w5_signature
from tvm_core.signing import W5R1Signer, create_w5_sign_fn

TESTNET = os.environ.get("TESTNET")


def _body_from_ext_boc(boc_b64: str) -> Cell:
    """Extract body cell from an external message BoC."""
    return parse_external_message(boc_b64)


class TestSignVerifyE2E:
    def test_sign_then_verify_signature(self, test_keypair):
        """Signed BoC body passes Ed25519 verification."""
        signer = W5R1Signer(bytes(test_keypair))
        msgs = [{"address": "0:" + "aa" * 32, "amount": "100000000"}]
        boc_b64 = signer.sign_transfer(seqno=1, valid_until=1999999999, messages=msgs)

        body = _body_from_ext_boc(boc_b64)
        ok, reason = verify_w5_signature(body, signer.public_key)
        assert ok, f"verify failed: {reason}"

    def test_invalid_signature_rejected(self):
        """BoC signed with one key is rejected when verified with another."""
        real_key = SigningKey.generate()
        wrong_key = SigningKey.generate()

        signer = W5R1Signer(bytes(real_key))
        msgs = [{"address": "0:" + "aa" * 32, "amount": "100000000"}]
        boc_b64 = signer.sign_transfer(seqno=1, valid_until=1999999999, messages=msgs)

        body = _body_from_ext_boc(boc_b64)
        ok, reason = verify_w5_signature(body, bytes(wrong_key.verify_key).hex())
        assert not ok
        assert "signature" in reason.lower()

    def test_full_parse_pipeline(self, test_keypair):
        """Sign -> parse body -> extract W5 fields."""
        signer = W5R1Signer(bytes(test_keypair))
        msgs = [
            {"address": "0:" + "aa" * 32, "amount": "100000000"},
            {"address": "0:" + "bb" * 32, "amount": "200000000"},
        ]
        boc_b64 = signer.sign_transfer(seqno=10, valid_until=1999999999, messages=msgs)

        body = _body_from_ext_boc(boc_b64)
        w5_msg = parse_w5_body(body)
        assert w5_msg.seqno == 10
        assert w5_msg.valid_until == 1999999999
        assert len(w5_msg.internal_messages) == 2

    @pytest.mark.skipif(not TESTNET, reason="Needs TESTNET=true and funded wallet")
    @pytest.mark.asyncio
    async def test_full_payment_flow(self, testnet_provider):
        """Full flow against testnet."""
        seed = os.environ.get("TEST_WALLET_SEED", "").encode()
        if len(seed) != 32:
            pytest.skip("TEST_WALLET_SEED must be 32 bytes")

        signer = W5R1Signer(seed, wallet_id=-3)
        seqno = await testnet_provider.get_seqno(signer.address)
        valid_until = int(time.time()) + 300

        msgs = [{"address": "0:" + "00" * 32, "amount": "10000000"}]
        boc_b64 = signer.sign_transfer(seqno=seqno, valid_until=valid_until, messages=msgs)

        body = _body_from_ext_boc(boc_b64)
        ok, reason = verify_w5_signature(body, signer.public_key)
        assert ok, f"Testnet verification failed: {reason}"

    @pytest.mark.asyncio
    async def test_sign_fn_e2e(self, test_keypair):
        """create_w5_sign_fn produces BoCs that pass verification."""
        sign_fn = create_w5_sign_fn(bytes(test_keypair))
        signer = W5R1Signer(bytes(test_keypair))

        msgs = [{"address": "0:" + "aa" * 32, "amount": "50000000"}]
        boc_b64 = await sign_fn(seqno=5, valid_until=1999999999, messages=msgs)

        body = _body_from_ext_boc(boc_b64)
        ok, _ = verify_w5_signature(body, signer.public_key)
        assert ok

        w5_msg = parse_w5_body(body)
        assert w5_msg.seqno == 5
