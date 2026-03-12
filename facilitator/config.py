"""Environment configuration for the facilitator service."""

from __future__ import annotations

import os

TONAPI_KEY: str = os.getenv("TONAPI_KEY", "")
RELAY_ADDRESS: str = os.getenv("RELAY_ADDRESS", "")
MAX_RELAY_COMMISSION: int = int(os.getenv("MAX_RELAY_COMMISSION", "500000"))
TESTNET: bool = os.getenv("TESTNET", "").lower() in ("1", "true", "yes")

# Supported networks — comma-separated CAIP-2 IDs
SUPPORTED_NETWORKS: str = os.getenv("SUPPORTED_NETWORKS", "tvm:-239,tvm:-3")

# Server
HOST: str = os.getenv("HOST", "0.0.0.0")
PORT: int = int(os.getenv("PORT", "8402"))
