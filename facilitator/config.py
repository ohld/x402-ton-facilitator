"""Environment configuration for the facilitator service."""

from __future__ import annotations

import os

from tvm_core.constants import DEFAULT_GAS_AMOUNT

TONAPI_KEY: str = os.getenv("TONAPI_KEY", "")
FACILITATOR_PRIVATE_KEY: str = os.getenv("FACILITATOR_PRIVATE_KEY", "")
GAS_AMOUNT: int = int(os.getenv("GAS_AMOUNT", str(DEFAULT_GAS_AMOUNT)))
TESTNET: bool = os.getenv("TESTNET", "").lower() in ("1", "true", "yes")

# Supported networks — comma-separated CAIP-2 IDs
SUPPORTED_NETWORKS: str = os.getenv("SUPPORTED_NETWORKS", "tvm:-239,tvm:-3")

# Server
HOST: str = os.getenv("HOST", "0.0.0.0")
PORT: int = int(os.getenv("PORT", "8402"))
