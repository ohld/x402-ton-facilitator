import os

import pytest
from nacl.signing import SigningKey

from tvm_core.tonapi import TonapiProvider


@pytest.fixture
def testnet_provider():
    return TonapiProvider(
        api_key=os.environ.get("TONAPI_KEY", ""),
        testnet=True,
    )


@pytest.fixture
def test_keypair():
    seed = b"x402_test_seed__________________"  # 32 bytes, deterministic
    return SigningKey(seed)
