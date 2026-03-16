"""E2E test: real mainnet payment via self-relay facilitator.

Requires:
- FACILITATOR_URL (default: https://ton-facilitator.okhlopkov.com)
- TEST_MNEMONIC: 24-word mnemonic for a W5R1 wallet with USDT
- PAYEE_ADDRESS: recipient wallet address (raw format)

Usage:
  export TEST_MNEMONIC="word1 word2 ..."
  export PAYEE_ADDRESS="0:..."
  python -m pytest tests/test_e2e_mainnet.py -v -s
"""

import asyncio
import os
import secrets
import time

import httpx
import pytest

from tvm_core.signing import W5R1Signer
from tvm_core.constants import USDT_MASTER, TVM_MAINNET

FACILITATOR_URL = os.environ.get("FACILITATOR_URL", "https://ton-facilitator.okhlopkov.com")
TEST_WALLET_SEED = os.environ.get("TEST_WALLET_SEED", "")
PAYEE_ADDRESS = os.environ.get("PAYEE_ADDRESS", "0:92433a576cbe56c4dcc86d94b497a2cf18a9baa9c8283fea28ea43eb3c25cfed")
PAYMENT_AMOUNT = "1000"  # 0.001 USDT (minimal amount for testing)


@pytest.mark.skipif(not TEST_WALLET_SEED, reason="TEST_WALLET_SEED not set")
class TestE2EMainnet:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.signer = W5R1Signer(bytes.fromhex(TEST_WALLET_SEED))
        self.client = httpx.AsyncClient(timeout=30)

    @pytest.mark.asyncio
    async def test_health(self):
        """Facilitator is healthy with funded wallet."""
        resp = await self.client.get(f"{FACILITATOR_URL}/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["architecture"] == "self-relay"
        assert data["facilitator_wallet"] is not None
        assert data["facilitator_balance"] is not None
        print(f"\n  Facilitator: {data['facilitator_wallet']}")
        print(f"  Balance: {data['facilitator_balance']}")

    @pytest.mark.asyncio
    async def test_prepare(self):
        """Facilitator /prepare returns valid signing data."""
        resp = await self.client.post(f"{FACILITATOR_URL}/prepare", json={
            "walletAddress": self.signer.address,
            "walletPublicKey": self.signer.public_key,
            "paymentRequirements": {
                "scheme": "exact",
                "network": TVM_MAINNET,
                "amount": PAYMENT_AMOUNT,
                "payTo": PAYEE_ADDRESS,
                "asset": USDT_MASTER,
            },
        })
        assert resp.status_code == 200, f"prepare failed: {resp.text}"
        data = resp.json()
        assert "seqno" in data
        assert "validUntil" in data
        assert "messages" in data
        assert len(data["messages"]) == 1  # exactly 1 jetton transfer
        print(f"\n  Seqno: {data['seqno']}")
        print(f"  Messages: {len(data['messages'])}")
        print(f"  Jetton wallet: {data['messages'][0]['address']}")

    @pytest.mark.asyncio
    async def test_full_payment_flow(self):
        """Full e2e: prepare → sign → verify → settle on mainnet."""
        print(f"\n  Client wallet: {self.signer.address}")
        print(f"  Payee: {PAYEE_ADDRESS}")
        print(f"  Amount: {PAYMENT_AMOUNT} nano USDT")

        # Step 1: Prepare
        print("\n  [1] Calling /prepare...")
        prepare_resp = await self.client.post(f"{FACILITATOR_URL}/prepare", json={
            "walletAddress": self.signer.address,
            "walletPublicKey": self.signer.public_key,
            "paymentRequirements": {
                "scheme": "exact",
                "network": TVM_MAINNET,
                "amount": PAYMENT_AMOUNT,
                "payTo": PAYEE_ADDRESS,
                "asset": USDT_MASTER,
            },
        })
        assert prepare_resp.status_code == 200, f"prepare failed: {prepare_resp.text}"
        prepare_data = prepare_resp.json()
        print(f"      Seqno: {prepare_data['seqno']}")

        # Step 2: Sign (auth_type="internal" for self-relay)
        print("  [2] Signing with W5R1 (internal_signed)...")
        settlement_boc = self.signer.sign_transfer(
            seqno=prepare_data["seqno"],
            valid_until=prepare_data["validUntil"],
            messages=prepare_data["messages"],
            auth_type="internal",
        )
        print(f"      BoC length: {len(settlement_boc)}")

        # Build payload
        payload = {
            "from": self.signer.address,
            "to": PAYEE_ADDRESS,
            "tokenMaster": USDT_MASTER,
            "amount": PAYMENT_AMOUNT,
            "validUntil": prepare_data["validUntil"],
            "nonce": secrets.token_hex(16),
            "settlementBoc": settlement_boc,
            "walletPublicKey": self.signer.public_key,
        }
        requirements = {
            "scheme": "exact",
            "network": TVM_MAINNET,
            "amount": PAYMENT_AMOUNT,
            "payTo": PAYEE_ADDRESS,
            "asset": USDT_MASTER,
        }

        # Step 3: Verify
        print("  [3] Calling /verify...")
        verify_resp = await self.client.post(f"{FACILITATOR_URL}/verify", json={
            "x402Version": 2,
            "paymentPayload": {"payload": payload},
            "paymentRequirements": requirements,
        })
        verify_data = verify_resp.json()
        print(f"      Valid: {verify_data.get('is_valid')}")
        if not verify_data.get("is_valid"):
            print(f"      Reason: {verify_data.get('invalid_reason')}")
        assert verify_data["is_valid"], f"verify failed: {verify_data}"

        # Step 4: Settle
        print("  [4] Calling /settle (self-relay, sponsoring gas)...")
        settle_resp = await self.client.post(f"{FACILITATOR_URL}/settle", json={
            "x402Version": 2,
            "paymentPayload": {"payload": payload},
            "paymentRequirements": requirements,
        })
        settle_data = settle_resp.json()
        print(f"      Success: {settle_data.get('success')}")
        print(f"      TX: {settle_data.get('transaction')}")
        if not settle_data.get("success"):
            print(f"      Error: {settle_data.get('error_reason')}")
        assert settle_data["success"], f"settle failed: {settle_data}"

        print(f"\n  === PAYMENT SETTLED ===")
        print(f"  Network: {settle_data.get('network')}")
        print(f"  Payer: {settle_data.get('payer')}")
        print(f"  TX: {settle_data.get('transaction')}")
