"""End-to-end tests for the signing -> verification pipeline."""

import os
import time

import pytest
from nacl.signing import SigningKey

from tvm_core.boc import parse_boc_and_extract, parse_external_message, parse_w5_body
from tvm_core.ed25519 import verify_w5_signature
from tvm_core.signing import W5R1Signer, create_w5_sign_fn
from tvm_core.verify import check_signature

TESTNET = os.environ.get("TESTNET")


class TestSignVerifyE2E:
    def test_sign_then_check_signature_rule(self, test_keypair):
        """Signed BoC passes the verify.py check_signature rule."""
        signer = W5R1Signer(bytes(test_keypair))
        msgs = [{"address": "0:" + "aa" * 32, "amount": "100000000"}]
        boc_b64 = signer.sign_transfer(seqno=1, valid_until=1999999999, messages=msgs)

        result = check_signature(boc_b64, signer.public_key)
        assert result.ok, f"check_signature failed: {result.reason}"

    def test_invalid_signature_rejected(self):
        """BoC signed with one key is rejected when verified with another."""
        real_key = SigningKey.generate()
        wrong_key = SigningKey.generate()

        signer = W5R1Signer(bytes(real_key))
        msgs = [{"address": "0:" + "aa" * 32, "amount": "100000000"}]
        boc_b64 = signer.sign_transfer(seqno=1, valid_until=1999999999, messages=msgs)

        result = check_signature(boc_b64, bytes(wrong_key.verify_key).hex())
        assert not result.ok
        assert "signature" in result.reason.lower()

    def test_full_parse_pipeline(self, test_keypair):
        """Sign -> parse_external_message -> parse_w5_body -> extract jetton transfers."""
        signer = W5R1Signer(bytes(test_keypair))
        msgs = [
            {"address": "0:" + "aa" * 32, "amount": "100000000"},
            {"address": "0:" + "bb" * 32, "amount": "200000000"},
        ]
        boc_b64 = signer.sign_transfer(
            seqno=10, valid_until=1999999999, messages=msgs
        )

        w5_msg, jetton_transfers = parse_boc_and_extract(boc_b64)
        assert w5_msg.seqno == 10
        assert w5_msg.valid_until == 1999999999
        assert len(w5_msg.internal_messages) == 2
        # No jetton transfer ops in plain TON transfers
        assert len(jetton_transfers) == 0

    @pytest.mark.skipif(not TESTNET, reason="Needs TESTNET=true and funded wallet")
    @pytest.mark.asyncio
    async def test_full_payment_flow(self, testnet_provider):
        """Full flow: sign, verify signature, check seqno against testnet.

        Requires: TESTNET=true, TONAPI_KEY set, and a funded testnet wallet.
        """
        seed = os.environ.get("TEST_WALLET_SEED", "").encode()
        if len(seed) != 32:
            pytest.skip("TEST_WALLET_SEED must be 32 bytes")

        signer = W5R1Signer(seed, wallet_id=-3)  # testnet wallet_id
        seqno = await testnet_provider.get_seqno(signer.address)
        valid_until = int(time.time()) + 300

        msgs = [{"address": "0:" + "00" * 32, "amount": "10000000"}]
        boc_b64 = signer.sign_transfer(
            seqno=seqno, valid_until=valid_until, messages=msgs
        )

        ok, reason = verify_w5_signature(boc_b64, signer.public_key)
        assert ok, f"Testnet signature verification failed: {reason}"

    @pytest.mark.asyncio
    async def test_sign_fn_e2e(self, test_keypair):
        """create_w5_sign_fn produces BoCs that pass full verification."""
        sign_fn = create_w5_sign_fn(bytes(test_keypair))
        signer = W5R1Signer(bytes(test_keypair))

        msgs = [{"address": "0:" + "aa" * 32, "amount": "50000000"}]
        boc_b64 = await sign_fn(seqno=5, valid_until=1999999999, messages=msgs)

        result = check_signature(boc_b64, signer.public_key)
        assert result.ok

        w5_msg, _ = parse_boc_and_extract(boc_b64)
        assert w5_msg.seqno == 5
