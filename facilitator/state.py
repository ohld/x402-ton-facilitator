"""Shared application state (singleton instances)."""

from __future__ import annotations

from tvm_core.tonapi import TonapiProvider
from x402_tvm.config import TvmFacilitatorConfig
from x402_tvm.exact.facilitator import ExactTvmFacilitatorScheme

from . import config as cfg

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
            facilitator_private_key=cfg.FACILITATOR_PRIVATE_KEY or None,
            gas_amount=cfg.GAS_AMOUNT,
            supported_networks=networks,
            testnet=cfg.TESTNET,
        )
        _facilitator = ExactTvmFacilitatorScheme(
            provider=provider,
            config=fac_config,
        )
    return _facilitator
