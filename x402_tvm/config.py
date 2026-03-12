"""Configuration types for TVM x402 mechanisms."""

from __future__ import annotations

from dataclasses import dataclass, field

from tvm_core.constants import DEFAULT_MAX_RELAY_COMMISSION, SUPPORTED_NETWORKS


@dataclass
class TvmFacilitatorConfig:
    """Configuration for the TVM facilitator scheme."""

    tonapi_key: str | None = None
    relay_address: str | None = None
    max_relay_commission: int = DEFAULT_MAX_RELAY_COMMISSION
    supported_networks: set[str] = field(default_factory=lambda: set(SUPPORTED_NETWORKS))
    testnet: bool = False
    settlement_timeout: int = 15


@dataclass
class TvmClientConfig:
    """Configuration for the TVM client scheme."""

    tonapi_key: str | None = None
    testnet: bool = False
