"""Negative-path tests: verify that invalid payments are rejected.

Tests verification rules without hitting the network:
- Expired payload (validUntil in the past)
- Wrong signature / different signer
- Amount mismatch
- Wrong recipient
- Wrong asset (token master)
"""

import secrets
import time

import pytest

from tvm_core.boc import compute_boc_hash
from tvm_core.constants import USDT_MASTER, TVM_MAINNET
from tvm_core.signing import W5R1Signer
from tvm_core.verify import (
    VerifyConfig,
    check_payment_intent,
    check_protocol,
    check_replay,
    check_signature,
    _seen_boc_hashes,
)
from tvm_core.types import TvmPaymentPayload


PAYEE = "0:" + "aa" * 32
FAKE_ASSET = "0:" + "bb" * 32

# Deterministic seeds for testing
SIGNER_SEED = b"x402_negative_test_signer_seed__"  # 32 bytes
WRONG_SEED = b"x402_negative_test_wrong_seed___"  # 32 bytes


@pytest.fixture
def signer():
    return W5R1Signer(SIGNER_SEED)


@pytest.fixture
def wrong_signer():
    return W5R1Signer(WRONG_SEED)


def _make_payload(signer, amount="10000", pay_to=PAYEE, valid_until=None, seqno=5):
    """Helper: build a valid signed payment payload."""
    if valid_until is None:
        valid_until = int(time.time()) + 120

    from tvm_core.jetton import build_jetton_transfer_payload

    jetton_payload = build_jetton_transfer_payload(
        destination=pay_to,
        amount=int(amount),
        response_destination=signer.address,
    )

    messages = [{
        "address": "0:" + "cc" * 32,  # jetton wallet address
        "amount": "50000000",  # 0.05 TON forward
        "payload": jetton_payload,
    }]

    boc = signer.sign_transfer(
        seqno=seqno,
        valid_until=valid_until,
        messages=messages,
        auth_type="internal",
    )

    return TvmPaymentPayload(
        **{
            "from": signer.address,
            "to": pay_to,
            "tokenMaster": USDT_MASTER,
            "amount": amount,
            "validUntil": valid_until,
            "nonce": secrets.token_hex(16),
            "settlementBoc": boc,
            "walletPublicKey": signer.public_key,
        }
    )


class TestExpiredPayload:
    def test_expired_valid_until(self, signer):
        """Reject payment where validUntil is in the past."""
        payload = _make_payload(signer, valid_until=int(time.time()) - 60)
        result = check_protocol("exact", TVM_MAINNET, VerifyConfig())
        assert result.ok

        # check_replay catches expiry
        # Mock provider with a simple class
        class MockProvider:
            async def get_seqno(self, addr):
                return 5
        import asyncio
        result = asyncio.get_event_loop().run_until_complete(
            check_replay(payload, MockProvider())
        )
        assert not result.ok
        assert "expired" in result.reason.lower()

    def test_valid_until_too_far(self, signer):
        """Reject payment where validUntil is too far in the future."""
        payload = _make_payload(signer, valid_until=int(time.time()) + 9999)

        class MockProvider:
            async def get_seqno(self, addr):
                return 5
        import asyncio
        result = asyncio.get_event_loop().run_until_complete(
            check_replay(payload, MockProvider())
        )
        assert not result.ok
        assert "too far" in result.reason.lower()


class TestWrongSignature:
    def test_different_signer_rejected(self, signer, wrong_signer):
        """Reject payment signed by a different key."""
        payload = _make_payload(wrong_signer)
        # Verify with the original signer's public key (mismatch)
        result = check_signature(payload.settlement_boc, signer.public_key)
        assert not result.ok
        assert "signature" in result.reason.lower()

    def test_correct_signer_accepted(self, signer):
        """Accept payment signed by the correct key."""
        payload = _make_payload(signer)
        result = check_signature(payload.settlement_boc, signer.public_key)
        assert result.ok


class TestAmountMismatch:
    @pytest.mark.asyncio
    async def test_insufficient_amount(self, signer):
        """Reject payment where amount < required."""
        payload = _make_payload(signer, amount="100")  # signed for 100

        class MockProvider:
            async def get_seqno(self, addr):
                return 5
            async def get_jetton_wallet(self, master, owner):
                return "0:" + "cc" * 32

        result = await check_payment_intent(
            payload,
            required_amount="10000",  # require 10000
            required_pay_to=PAYEE,
            required_asset=USDT_MASTER,
            provider=MockProvider(),
        )
        assert not result.ok
        assert "insufficient" in result.reason.lower() or "amount" in result.reason.lower()


class TestWrongRecipient:
    @pytest.mark.asyncio
    async def test_wrong_destination(self, signer):
        """Reject payment to wrong recipient."""
        wrong_payee = "0:" + "dd" * 32
        payload = _make_payload(signer, pay_to=wrong_payee)

        class MockProvider:
            async def get_seqno(self, addr):
                return 5
            async def get_jetton_wallet(self, master, owner):
                return "0:" + "cc" * 32

        result = await check_payment_intent(
            payload,
            required_amount="10000",
            required_pay_to=PAYEE,  # expected PAYEE, but BoC sends to wrong_payee
            required_asset=USDT_MASTER,
            provider=MockProvider(),
        )
        assert not result.ok
        assert "transfer" in result.reason.lower() or "destination" in result.reason.lower()


class TestWrongAsset:
    @pytest.mark.asyncio
    async def test_token_mismatch(self, signer):
        """Reject payment with wrong token master."""
        payload = _make_payload(signer)
        payload.token_master = FAKE_ASSET  # claim it's a different token

        class MockProvider:
            async def get_seqno(self, addr):
                return 5

        result = await check_payment_intent(
            payload,
            required_amount="10000",
            required_pay_to=PAYEE,
            required_asset=USDT_MASTER,
            provider=MockProvider(),
        )
        assert not result.ok
        assert "mismatch" in result.reason.lower()


class TestProtocol:
    def test_wrong_scheme(self):
        result = check_protocol("flexible", TVM_MAINNET, VerifyConfig())
        assert not result.ok
        assert "scheme" in result.reason.lower()

    def test_wrong_network(self):
        result = check_protocol("exact", "evm:1", VerifyConfig())
        assert not result.ok
        assert "network" in result.reason.lower()

    def test_correct_protocol(self):
        result = check_protocol("exact", TVM_MAINNET, VerifyConfig())
        assert result.ok


class TestReplayProtection:
    def test_duplicate_boc_rejected(self, signer):
        """Reject BoC that was already seen."""
        payload = _make_payload(signer)
        boc_hash = compute_boc_hash(payload.settlement_boc)

        # Simulate already seen
        _seen_boc_hashes.add(boc_hash)

        class MockProvider:
            async def get_seqno(self, addr):
                return 5
        import asyncio
        result = asyncio.get_event_loop().run_until_complete(
            check_replay(payload, MockProvider())
        )
        assert not result.ok
        assert "duplicate" in result.reason.lower()

        # Cleanup
        _seen_boc_hashes.discard(boc_hash)

    def test_stale_seqno_rejected(self, signer):
        """Reject BoC with seqno < on-chain seqno."""
        payload = _make_payload(signer, seqno=3)

        class MockProvider:
            async def get_seqno(self, addr):
                return 10  # on-chain is 10, BoC has 3
        import asyncio
        result = asyncio.get_event_loop().run_until_complete(
            check_replay(payload, MockProvider())
        )
        assert not result.ok
        assert "stale" in result.reason.lower() or "seqno" in result.reason.lower()
