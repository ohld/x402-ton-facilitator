"""Shared application state (singleton instances)."""

from __future__ import annotations

from tvm_core.state import PaymentStateStore
from tvm_core.tonapi import TonapiProvider
from x402_tvm.config import TvmFacilitatorConfig
from x402_tvm.exact.facilitator import ExactTvmFacilitatorScheme

from . import config as cfg

# Provider instance (created on startup)
_provider: TonapiProvider | None = None
_facilitator: ExactTvmFacilitatorScheme | None = None


def get_provider() -> TonapiProvider:
    global _provider
    if _provider is None:
        _provider = TonapiProvider(
            api_key=cfg.TONAPI_KEY or None,
            testnet=cfg.TESTNET,
        )
    return _provider


def get_facilitator() -> ExactTvmFacilitatorScheme:
    global _facilitator
    if _facilitator is None:
        provider = get_provider()
        networks = set(n.strip() for n in cfg.SUPPORTED_NETWORKS.split(","))
        fac_config = TvmFacilitatorConfig(
            tonapi_key=cfg.TONAPI_KEY or None,
            relay_address=cfg.RELAY_ADDRESS or None,
            max_relay_commission=cfg.MAX_RELAY_COMMISSION,
            supported_networks=networks,
            testnet=cfg.TESTNET,
        )
        _facilitator = ExactTvmFacilitatorScheme(
            provider=provider,
            settler=provider,  # TonapiProvider implements both protocols
            config=fac_config,
        )
    return _facilitator
