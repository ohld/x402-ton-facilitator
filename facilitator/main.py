"""FastAPI facilitator service for TON x402 payments.

Endpoints:
- GET  /supported — payment kinds this facilitator supports
- POST /verify    — verify a payment payload
- POST /settle    — settle a payment on-chain (idempotent)
- GET  /health    — service health check
"""

from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from tvm_core.constants import SCHEME_EXACT, TVM_MAINNET, TVM_TESTNET

from . import config as cfg
from .state import get_facilitator, get_provider

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("facilitator")

app = FastAPI(
    title="x402 TON Facilitator",
    description="Verifies and settles x402 payments on TON blockchain",
    version="0.1.0",
)

START_TIME = time.time()


# --- Request/Response models ---


class VerifyRequest(BaseModel):
    x402_version: int = Field(alias="x402Version", default=2)
    payment_payload: dict[str, Any] = Field(alias="paymentPayload")
    payment_requirements: dict[str, Any] = Field(alias="paymentRequirements")

    model_config = {"populate_by_name": True}


class SettleRequest(BaseModel):
    x402_version: int = Field(alias="x402Version", default=2)
    payment_payload: dict[str, Any] = Field(alias="paymentPayload")
    payment_requirements: dict[str, Any] = Field(alias="paymentRequirements")

    model_config = {"populate_by_name": True}


class SupportedKind(BaseModel):
    x402_version: int = Field(alias="x402Version", default=2)
    scheme: str
    network: str
    extra: dict[str, Any] | None = None

    model_config = {"populate_by_name": True}


class SupportedResponse(BaseModel):
    kinds: list[SupportedKind]
    extensions: list[str] = []
    signers: dict[str, list[str]] = {}


# --- Middleware ---


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    elapsed = (time.time() - start) * 1000
    logger.info(
        "%s %s %d %.0fms",
        request.method,
        request.url.path,
        response.status_code,
        elapsed,
    )
    return response


# --- Endpoints ---


@app.get("/supported")
async def supported() -> SupportedResponse:
    """Return payment kinds this facilitator supports."""
    facilitator = get_facilitator()
    networks = list(facilitator._config.supported_networks)

    kinds = []
    for network in networks:
        extra = facilitator.get_extra(network)
        kinds.append(
            SupportedKind(
                x402Version=2,
                scheme=SCHEME_EXACT,
                network=network,
                extra=extra,
            )
        )

    return SupportedResponse(kinds=kinds)


@app.post("/verify")
async def verify(request: VerifyRequest) -> JSONResponse:
    """Verify a payment payload."""
    facilitator = get_facilitator()

    # Extract the inner payload dict
    payload_dict = request.payment_payload
    inner_payload = payload_dict.get("payload", payload_dict)

    requirements = request.payment_requirements

    result = await facilitator.verify(inner_payload, requirements)

    status_code = 200 if result["is_valid"] else 400
    return JSONResponse(content=result, status_code=status_code)


@app.post("/settle")
async def settle(request: SettleRequest) -> JSONResponse:
    """Settle a payment on-chain. Idempotent."""
    facilitator = get_facilitator()

    payload_dict = request.payment_payload
    inner_payload = payload_dict.get("payload", payload_dict)

    requirements = request.payment_requirements

    result = await facilitator.settle(inner_payload, requirements)

    status_code = 200 if result["success"] else 400
    return JSONResponse(content=result, status_code=status_code)


@app.get("/health")
async def health() -> dict[str, Any]:
    """Health check with uptime and provider status."""
    uptime = time.time() - START_TIME

    provider_ok = False
    try:
        provider = get_provider()
        # Quick connectivity check — get gasless config
        config = await provider.get_gasless_config()
        provider_ok = "relay_address" in config or "relayAddress" in config
    except Exception as e:
        logger.warning("Provider health check failed: %s", e)

    return {
        "status": "ok" if provider_ok else "degraded",
        "uptime_seconds": round(uptime),
        "provider": "tonapi",
        "provider_ok": provider_ok,
        "testnet": cfg.TESTNET,
        "version": "0.1.0",
    }
