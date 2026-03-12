"""TVM server implementation for the Exact payment scheme.

Handles price parsing and requirement enhancement for TON payments.
"""

from __future__ import annotations

from typing import Any

from tvm_core.constants import SCHEME_EXACT, USDT_MASTER


class ExactTvmServerScheme:
    """TVM server for the 'exact' payment scheme.

    Implements the SchemeNetworkServer protocol from x402 SDK.
    """

    scheme = SCHEME_EXACT

    def __init__(self, default_asset: str = USDT_MASTER):
        self._default_asset = default_asset

    def parse_price(self, price: str | float, network: str) -> dict[str, Any]:
        """Convert USD price to USDT nano amount.

        USDT on TON has 6 decimals, so $0.01 = 10000 nano.

        Args:
            price: Price as string ("$0.01", "0.01") or float.
            network: Network identifier (unused, kept for interface).

        Returns:
            AssetAmount dict with 'amount' and 'asset'.
        """
        if isinstance(price, str):
            clean = price.replace("$", "").strip()
            usd = float(clean)
        else:
            usd = float(price)

        nano = int(usd * 1_000_000)

        return {
            "amount": str(nano),
            "asset": self._default_asset,
        }

    def enhance_payment_requirements(
        self,
        requirements: dict[str, Any],
        supported_kind: dict[str, Any] | None = None,
        extensions: list[str] | None = None,
    ) -> dict[str, Any]:
        """Add TVM-specific fields to payment requirements.

        Adds relay address and commission info to extra dict.

        Args:
            requirements: Base payment requirements.
            supported_kind: Supported kind from facilitator (may have relay info).
            extensions: List of enabled extension keys.

        Returns:
            Enhanced requirements dict.
        """
        extra = dict(requirements.get("extra", {}))

        if supported_kind and supported_kind.get("extra"):
            sk_extra = supported_kind["extra"]
            if "relayAddress" in sk_extra:
                extra["relayAddress"] = sk_extra["relayAddress"]

        requirements = dict(requirements)
        requirements["extra"] = extra
        return requirements
