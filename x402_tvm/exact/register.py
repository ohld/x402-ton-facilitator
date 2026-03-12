"""Registration helpers for TVM exact payment schemes."""

from __future__ import annotations

from typing import Any

from tvm_core.constants import SUPPORTED_NETWORKS
from tvm_core.providers import TonProvider, TonSettler

from ..config import TvmClientConfig, TvmFacilitatorConfig


def register_exact_tvm_facilitator(
    facilitator: Any,
    provider: TonProvider,
    settler: TonSettler,
    networks: str | list[str] | None = None,
    config: TvmFacilitatorConfig | None = None,
) -> Any:
    """Register TVM exact payment scheme to an x402Facilitator.

    Args:
        facilitator: x402Facilitator instance.
        provider: TON provider for verification.
        settler: TON settler for settlement.
        networks: Network(s) to register. Default: all supported.
        config: Optional facilitator configuration.

    Returns:
        Facilitator for chaining.
    """
    from .facilitator import ExactTvmFacilitatorScheme

    scheme = ExactTvmFacilitatorScheme(provider, settler, config)

    if networks is None:
        networks = list(SUPPORTED_NETWORKS)
    elif isinstance(networks, str):
        networks = [networks]

    facilitator.register(networks, scheme)
    return facilitator


def register_exact_tvm_client(
    client: Any,
    wallet_address: str,
    public_key: str,
    sign_fn: Any,
    provider: TonProvider,
    settler: TonSettler,
    networks: str | list[str] | None = None,
    config: TvmClientConfig | None = None,
) -> Any:
    """Register TVM exact payment scheme to an x402Client.

    Args:
        client: x402Client instance.
        wallet_address: Sender W5 wallet address.
        public_key: Ed25519 public key (hex).
        sign_fn: Signing function.
        provider: TON provider.
        settler: TON settler.
        networks: Network(s) to register. Default: tvm:* wildcard.
        config: Optional client configuration.

    Returns:
        Client for chaining.
    """
    from .client import ExactTvmClientScheme

    scheme = ExactTvmClientScheme(
        wallet_address=wallet_address,
        public_key=public_key,
        sign_fn=sign_fn,
        provider=provider,
        settler=settler,
        config=config,
    )

    if networks is None:
        client.register("tvm:*", scheme)
    else:
        if isinstance(networks, str):
            networks = [networks]
        for network in networks:
            client.register(network, scheme)

    return client


def register_exact_tvm_server(
    server: Any,
    networks: str | list[str] | None = None,
    default_asset: str | None = None,
) -> Any:
    """Register TVM exact payment scheme to an x402ResourceServer.

    Args:
        server: x402ResourceServer instance.
        networks: Network(s) to register. Default: tvm:* wildcard.
        default_asset: Default token master address.

    Returns:
        Server for chaining.
    """
    from .server import ExactTvmServerScheme

    kwargs = {}
    if default_asset:
        kwargs["default_asset"] = default_asset

    scheme = ExactTvmServerScheme(**kwargs)

    if networks is None:
        server.register("tvm:*", scheme)
    else:
        if isinstance(networks, str):
            networks = [networks]
        for network in networks:
            server.register(network, scheme)

    return server
