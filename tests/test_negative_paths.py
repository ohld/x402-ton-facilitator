"""Negative-path tests: verify that invalid payments are rejected.

Tests verification rules without hitting the network.
Uses the new minimal payload: {settlementBoc, asset}.
"""

import base64
import secrets
import time

import pytest
from pytoniq_core import Builder, Cell, Address

from tvm_core.boc import compute_boc_hash, parse_external_message
from tvm_core.constants import USDT_MASTER, TVM_MAINNET
from tvm_core.ed25519 import verify_w5_signature
from tvm_core.signing import W5R1Signer
from tvm_core.verify import (
    VerifyConfig,
    check_payment_intent,
    check_protocol,
    check_replay,
    mark_boc_settled,
    _seen_boc_hashes,
)
from tvm_core.types import TvmPaymentPayload


PAYEE = "0:" + "aa" * 32
FAKE_ASSET = "0:" + "bb" * 32

SIGNER_SEED = b"x402_negative_test_signer_seed__"
WRONG_SEED = b"x402_negative_test_wrong_seed___"


@pytest.fixture
def signer():
    return W5R1Signer(SIGNER_SEED)


@pytest.fixture
def wrong_signer():
    return W5R1Signer(WRONG_SEED)


def _build_internal_boc(signer, body_cell, state_init_cell=None):
    """Wrap a W5 body in an internal message BoC (new format)."""
    b = Builder()
    b.store_bit(0)  # int_msg_info$0
    b.store_bit(1)  # ihr_disabled
    b.store_bit(1)  # bounce
    b.store_bit(0)  # bounced
    b.store_uint(0, 2)  # src: addr_none
    b.store_address(Address(signer.address))
    b.store_coins(0)
    b.store_bit(0)  # no extra currencies
    b.store_coins(0)  # ihr_fee
    b.store_coins(0)  # fwd_fee
    b.store_uint(0, 64)  # created_lt
    b.store_uint(0, 32)  # created_at
    if state_init_cell:
        b.store_bit(1)
        b.store_bit(1)
        b.store_ref(state_init_cell)
    else:
        b.store_bit(0)
    b.store_bit(1)  # body as ref
    b.store_ref(body_cell)
    return base64.b64encode(b.end_cell().to_boc()).decode()


def _make_payload(signer, amount="10000", pay_to=PAYEE, valid_until=None, seqno=5, asset=USDT_MASTER):
    """Build a valid signed payment payload (new minimal format)."""
    if valid_until is None:
        valid_until = int(time.time()) + 120

    from tvm_core.jetton import build_jetton_transfer_payload

    jetton_payload = build_jetton_transfer_payload(
        destination=pay_to,
        amount=int(amount),
        response_destination=signer.address,
    )

    messages = [{
        "address": "0:" + "cc" * 32,
        "amount": "50000000",
        "payload": jetton_payload,
    }]

    # Sign transfer (produces external BoC for signing)
    ext_boc = signer.sign_transfer(
        seqno=seqno,
        valid_until=valid_until,
        messages=messages,
        auth_type="internal",
    )

    # Extract body from external message and wrap in internal message BoC
    body_cell = parse_external_message(ext_boc)
    settlement_boc = _build_internal_boc(signer, body_cell)

    return TvmPaymentPayload(
        settlementBoc=settlement_boc,
        asset=asset,
    )


class TestExpiredPayload:
    def test_expired_valid_until(self, signer):
        """Reject payment where validUntil is in the past."""
        payload = _make_payload(signer, valid_until=int(time.time()) - 60)

        class MockProvider:
            async def get_seqno(self, addr):
                return 5
            async def get_public_key(self, addr):
                return signer.public_key

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
            async def get_public_key(self, addr):
                return signer.public_key

        import asyncio
        result = asyncio.get_event_loop().run_until_complete(
            check_replay(payload, MockProvider())
        )
        assert not result.ok
        assert "too far" in result.reason.lower()


class TestWrongSignature:
    def test_different_signer_rejected(self, signer, wrong_signer):
        """Reject when body verified with wrong public key."""
        payload = _make_payload(wrong_signer)

        from tvm_core.boc import parse_settlement_boc
        settlement = parse_settlement_boc(payload.settlement_boc)
        ok, reason = verify_w5_signature(settlement.body_cell, signer.public_key)
        assert not ok
        assert "signature" in reason.lower()

    def test_correct_signer_accepted(self, signer):
        """Accept when body verified with correct public key."""
        payload = _make_payload(signer)

        from tvm_core.boc import parse_settlement_boc
        settlement = parse_settlement_boc(payload.settlement_boc)
        ok, reason = verify_w5_signature(settlement.body_cell, signer.public_key)
        assert ok


class TestAmountMismatch:
    @pytest.mark.asyncio
    async def test_insufficient_amount(self, signer):
        """Reject payment where BoC amount != required."""
        payload = _make_payload(signer, amount="100")

        class MockProvider:
            async def get_seqno(self, addr):
                return 5
            async def get_jetton_wallet(self, master, owner):
                return "0:" + "cc" * 32
            async def get_public_key(self, addr):
                return signer.public_key

        result = await check_payment_intent(
            payload,
            required_amount="10000",
            required_pay_to=PAYEE,
            required_asset=USDT_MASTER,
            provider=MockProvider(),
        )
        assert not result.ok
        assert "amount" in result.reason.lower() or "no valid" in result.reason.lower()


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
            async def get_public_key(self, addr):
                return signer.public_key

        result = await check_payment_intent(
            payload,
            required_amount="10000",
            required_pay_to=PAYEE,
            required_asset=USDT_MASTER,
            provider=MockProvider(),
        )
        assert not result.ok
        assert "no valid" in result.reason.lower() or "mismatch" in result.reason.lower()


class TestWrongAsset:
    @pytest.mark.asyncio
    async def test_token_mismatch(self, signer):
        """Reject payment with wrong asset in payload."""
        payload = _make_payload(signer, asset=FAKE_ASSET)

        class MockProvider:
            async def get_seqno(self, addr):
                return 5
            async def get_public_key(self, addr):
                return signer.public_key

        result = await check_payment_intent(
            payload,
            required_amount="10000",
            required_pay_to=PAYEE,
            required_asset=USDT_MASTER,
            provider=MockProvider(),
        )
        assert not result.ok
        assert "mismatch" in result.reason.lower()


class TestSourceJettonWallet:
    @pytest.mark.asyncio
    async def test_wrong_source_wallet(self, signer):
        """Reject when BoC targets different source Jetton wallet than expected."""
        payload = _make_payload(signer)

        class MockProvider:
            async def get_seqno(self, addr):
                return 5
            async def get_jetton_wallet(self, master, owner):
                return "0:" + "ee" * 32  # different from BoC's "0:cc..cc"
            async def get_public_key(self, addr):
                return signer.public_key

        result = await check_payment_intent(
            payload,
            required_amount="10000",
            required_pay_to=PAYEE,
            required_asset=USDT_MASTER,
            provider=MockProvider(),
        )
        assert not result.ok
        assert "source" in result.reason.lower() or "jetton wallet" in result.reason.lower()


class TestProtocol:
    def test_wrong_scheme(self):
        result = check_protocol("flexible", TVM_MAINNET, VerifyConfig())
        assert not result.ok

    def test_wrong_network(self):
        result = check_protocol("exact", "evm:1", VerifyConfig())
        assert not result.ok

    def test_correct_protocol(self):
        result = check_protocol("exact", TVM_MAINNET, VerifyConfig())
        assert result.ok


class TestReplayProtection:
    def test_duplicate_settle_rejected(self, signer):
        """Reject BoC that was already settled."""
        payload = _make_payload(signer)

        # Mark as settled
        assert mark_boc_settled(payload.settlement_boc) == True
        # Second attempt should be rejected
        assert mark_boc_settled(payload.settlement_boc) == False

        # Cleanup
        boc_hash = compute_boc_hash(payload.settlement_boc)
        _seen_boc_hashes.discard(boc_hash)

    def test_stale_seqno_rejected(self, signer):
        """Reject BoC with seqno != on-chain seqno."""
        payload = _make_payload(signer, seqno=3)

        class MockProvider:
            async def get_seqno(self, addr):
                return 10  # on-chain is 10, BoC has 3
            async def get_public_key(self, addr):
                return signer.public_key

        import asyncio
        result = asyncio.get_event_loop().run_until_complete(
            check_replay(payload, MockProvider())
        )
        assert not result.ok
        assert "seqno" in result.reason.lower()
