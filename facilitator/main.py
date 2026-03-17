"""FastAPI facilitator service for TON x402 payments.

Self-relay architecture: the facilitator holds TON and sponsors gas for
user payments. No third-party gasless relay needed.

Endpoints:
- POST /prepare  — client calls to get seqno + messages before signing
- POST /verify   — verify a payment payload (required)
- POST /settle   — settle a payment on-chain via self-relay (idempotent)
- GET  /supported — payment kinds this facilitator supports
- GET  /health   — service health + facilitator wallet balance
"""

from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from tvm_core.constants import SCHEME_EXACT
from tvm_core.types import PrepareRequest

from . import config as cfg
from .state import get_facilitator, get_provider

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("facilitator")

app = FastAPI(
    title="x402 TON Facilitator",
    description="Verifies and settles x402 payments on TON — self-relay gas sponsorship",
    version="0.2.0",
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
    model_config = {"populate_by_name": True}


class SupportedResponse(BaseModel):
    kinds: list[SupportedKind]


# --- Middleware ---


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    elapsed = (time.time() - start) * 1000
    logger.info("%s %s %d %.0fms", request.method, request.url.path, response.status_code, elapsed)
    return response


FACILITATOR_URL = "https://ton-facilitator.okhlopkov.com"
GITHUB_URL = "https://github.com/ohld/x402-ton-facilitator"

LANDING_HTML = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>x402 TON Facilitator</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, system-ui, sans-serif; background: #0a0a0a; color: #e0e0e0; padding: 2rem; max-width: 720px; margin: 0 auto; line-height: 1.6; }}
  h1 {{ color: #fff; font-size: 1.5rem; margin-bottom: 0.5rem; }}
  .subtitle {{ color: #888; margin-bottom: 2rem; }}
  .section {{ background: #141414; border: 1px solid #222; border-radius: 8px; padding: 1.25rem; margin-bottom: 1.25rem; }}
  .section h2 {{ color: #ccc; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.75rem; }}
  code {{ font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.85rem; }}
  pre {{ background: #0d0d0d; border: 1px solid #1a1a1a; border-radius: 6px; padding: 1rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
  .endpoint {{ display: flex; gap: 0.5rem; align-items: center; padding: 0.4rem 0; }}
  .method {{ background: #1a3a1a; color: #4ade80; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; font-family: monospace; min-width: 3.5rem; text-align: center; }}
  .method.post {{ background: #1a2a3a; color: #60a5fa; }}
  .path {{ color: #e0e0e0; font-family: monospace; font-size: 0.85rem; }}
  .desc {{ color: #666; font-size: 0.8rem; margin-left: auto; }}
  a {{ color: #60a5fa; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .badge {{ display: inline-block; background: #1a2a1a; color: #4ade80; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-family: monospace; }}
  .links {{ display: flex; gap: 1rem; flex-wrap: wrap; }}
  .links a {{ background: #141414; border: 1px solid #222; padding: 0.4rem 0.8rem; border-radius: 4px; font-size: 0.85rem; }}
</style>
</head>
<body>
<h1>x402 TON Facilitator</h1>
<p class="subtitle">Self-relay gas sponsorship for <a href="https://github.com/coinbase/x402">x402</a> payments on TON</p>

<div class="section">
<h2>Architecture</h2>
<p style="color:#aaa; font-size:0.85rem;">
The facilitator acts as both verifier and gas sponsor.
Clients sign offline, merchants add middleware, the facilitator handles all blockchain interaction.
Same clean separation as EVM EIP-3009.
</p>
</div>

<div class="section">
<h2>Status</h2>
<span class="badge">mainnet + testnet</span>
<span class="badge">tvm:-239</span>
<span class="badge">tvm:-3</span>
<span class="badge">self-relay</span>
</div>

<div class="section">
<h2>Endpoints</h2>
<div class="endpoint"><span class="method post">POST</span><span class="path">/prepare</span><span class="desc">get signing data (seqno, messages)</span></div>
<div class="endpoint"><span class="method post">POST</span><span class="path">/verify</span><span class="desc">verify payment (required)</span></div>
<div class="endpoint"><span class="method post">POST</span><span class="path">/settle</span><span class="desc">settle on-chain via self-relay</span></div>
<div class="endpoint"><span class="method">GET</span><span class="path">/supported</span><span class="desc">payment kinds</span></div>
<div class="endpoint"><span class="method">GET</span><span class="path">/health</span><span class="desc">service health + wallet balance</span></div>
<div class="endpoint"><span class="method">GET</span><span class="path">/docs</span><span class="desc">OpenAPI docs</span></div>
</div>

<div class="section">
<h2>Flow</h2>
<pre>Client          Merchant           Facilitator          TON
  |--- GET /resource -->|                  |                |
  |<-- 402 + requirements|                 |                |
  |--- POST /prepare ------------------>|                   |
  |<-- seqno, messages -----------------| (queries seqno)   |
  | [sign locally]      |                 |                 |
  |--- GET /resource + X-PAYMENT -->|     |                 |
  |                     |-- POST /verify ->|                |
  |                     |<- is_valid ------|                 |
  |                     |-- POST /settle ->|                |
  |                     |                  |-- internal msg -->|
  |                     |                  |   (TON for gas)   |
  |                     |<- tx_hash -------|<-- confirmed -----|
  |<-- 200 + data ------|                  |                   |</pre>
</div>

<div class="section">
<h2>Links</h2>
<div class="links">
<a href="{GITHUB_URL}">GitHub</a>
<a href="{FACILITATOR_URL}/docs">API Docs</a>
<a href="https://github.com/coinbase/x402">x402 Protocol</a>
<a href="https://github.com/coinbase/x402/pull/1455">TON Spec PR</a>
</div>
</div>
</body>
</html>
"""


# --- Endpoints ---


@app.get("/", include_in_schema=False)
async def landing(request: Request):
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return HTMLResponse(LANDING_HTML)
    return {
        "name": "x402 TON Facilitator",
        "version": "0.2.0",
        "architecture": "self-relay",
        "facilitator_url": FACILITATOR_URL,
        "networks": ["tvm:-239", "tvm:-3"],
        "endpoints": {
            "prepare": "POST /prepare",
            "verify": "POST /verify",
            "settle": "POST /settle",
            "supported": "GET /supported",
            "health": "GET /health",
        },
        "source": GITHUB_URL,
    }


@app.get("/supported")
async def supported() -> JSONResponse:
    """Return payment kinds this facilitator supports."""
    facilitator = get_facilitator()
    networks = list(facilitator._config.supported_networks)
    kinds = [
        SupportedKind(x402Version=2, scheme=SCHEME_EXACT, network=n)
        for n in networks
    ]
    resp = SupportedResponse(kinds=kinds)
    return JSONResponse(content=resp.model_dump(by_alias=True))


@app.post("/prepare")
async def prepare(request: PrepareRequest) -> JSONResponse:
    """Prepare signing data for a client.

    Returns seqno, validUntil, walletId, and messages to sign.
    The client signs with authType='internal' and sends the BoC back.
    """
    facilitator = get_facilitator()
    try:
        result = await facilitator.prepare(
            wallet_address=request.wallet_address,
            wallet_public_key=request.wallet_public_key,
            requirements=request.payment_requirements,
        )
        return JSONResponse(content=result)
    except Exception as e:
        logger.error("Prepare failed: %s", e)
        return JSONResponse(
            content={"error": str(e)},
            status_code=400,
        )


@app.post("/verify")
async def verify(request: VerifyRequest) -> JSONResponse:
    """Verify a payment payload. Required before settlement."""
    facilitator = get_facilitator()
    payload_dict = request.payment_payload
    inner_payload = payload_dict.get("payload", payload_dict)
    requirements = request.payment_requirements

    result = await facilitator.verify(inner_payload, requirements)
    status_code = 200 if result["isValid"] else 400
    return JSONResponse(content=result, status_code=status_code)


@app.post("/settle")
async def settle(request: SettleRequest) -> JSONResponse:
    """Settle a payment on-chain via self-relay. Idempotent."""
    facilitator = get_facilitator()
    payload_dict = request.payment_payload
    inner_payload = payload_dict.get("payload", payload_dict)
    requirements = request.payment_requirements

    result = await facilitator.settle(inner_payload, requirements)
    status_code = 200 if result["success"] else 400
    return JSONResponse(content=result, status_code=status_code)


@app.get("/health")
async def health() -> dict[str, Any]:
    """Health check with uptime, provider status, and facilitator wallet balance."""
    uptime = time.time() - START_TIME
    facilitator = get_facilitator()

    provider_ok = False
    wallet_balance = None
    wallet_address = None

    try:
        provider = get_provider()
        # Quick connectivity check
        state = await provider.get_account_state(
            "0:0000000000000000000000000000000000000000000000000000000000000000"
        )
        provider_ok = True
    except Exception as e:
        logger.warning("Provider health check failed: %s", e)

    if facilitator.relay:
        wallet_address = facilitator.relay.address
        try:
            balance = await facilitator.relay.get_balance()
            wallet_balance = f"{balance / 1e9:.4f} TON"
        except Exception:
            wallet_balance = "unknown"

    return {
        "status": "ok" if provider_ok else "degraded",
        "uptime_seconds": round(uptime),
        "architecture": "self-relay",
        "provider": "tonapi",
        "provider_ok": provider_ok,
        "testnet": cfg.TESTNET,
        "version": "0.2.0",
        "facilitator_wallet": wallet_address,
        "facilitator_balance": wallet_balance,
    }
