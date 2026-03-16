"""Configuration types for TVM x402 mechanisms."""

from __future__ import annotations

from dataclasses import dataclass, field

from tvm_core.constants import DEFAULT_GAS_AMOUNT, SUPPORTED_NETWORKS


@dataclass
class TvmFacilitatorConfig:
    """Configuration for the TVM facilitator scheme.

    The facilitator acts as a self-relay: it holds TON and sponsors gas
    for user payments. No third-party gasless relay is needed.
    """

    tonapi_key: str | None = None
    facilitator_private_key: str | None = None  # hex-encoded Ed25519 seed
    gas_amount: int = DEFAULT_GAS_AMOUNT
    supported_networks: set[str] = field(default_factory=lambda: set(SUPPORTED_NETWORKS))
    testnet: bool = False
    settlement_timeout: int = 15


@dataclass
class TvmClientConfig:
    """Configuration for the TVM client scheme."""

    facilitator_url: str = "https://ton-facilitator.okhlopkov.com"
