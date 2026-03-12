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
from fastapi.responses import HTMLResponse, JSONResponse
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
  .copy-btn {{ background: #222; color: #aaa; border: 1px solid #333; border-radius: 4px; padding: 0.3rem 0.7rem; cursor: pointer; font-size: 0.75rem; float: right; }}
  .copy-btn:hover {{ background: #333; color: #fff; }}
  .links {{ display: flex; gap: 1rem; flex-wrap: wrap; }}
  .links a {{ background: #141414; border: 1px solid #222; padding: 0.4rem 0.8rem; border-radius: 4px; font-size: 0.85rem; }}
</style>
</head>
<body>
<h1>x402 TON Facilitator</h1>
<p class="subtitle">Verify and settle <a href="https://github.com/coinbase/x402">x402</a> payments on TON &mdash; USDT via gasless relay</p>

<div class="section">
<h2>Status</h2>
<span class="badge">mainnet + testnet</span>
<span class="badge">tvm:-239</span>
<span class="badge">tvm:-3</span>
</div>

<div class="section">
<h2>Endpoints</h2>
<div class="endpoint"><span class="method">GET</span><span class="path">/supported</span><span class="desc">payment kinds</span></div>
<div class="endpoint"><span class="method post">POST</span><span class="path">/verify</span><span class="desc">verify payment</span></div>
<div class="endpoint"><span class="method post">POST</span><span class="path">/settle</span><span class="desc">settle on-chain</span></div>
<div class="endpoint"><span class="method">GET</span><span class="path">/health</span><span class="desc">service health</span></div>
<div class="endpoint"><span class="method">GET</span><span class="path">/docs</span><span class="desc">OpenAPI docs</span></div>
</div>

<div class="section">
<h2>Agent Prompt</h2>
<button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('prompt').textContent)">Copy</button>
<pre id="prompt">Use {FACILITATOR_URL} as the x402 facilitator for TON payments.

To accept USDT payments on TON via x402 protocol:
1. Install: pip install httpx
2. Point your x402 resource server's facilitator_url to {FACILITATOR_URL}
3. Set payment requirements: scheme="exact", network="tvm:-239", asset="0:b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe" (USDT)
4. The facilitator handles verify + settle via TONAPI gasless relay

Check supported payments: curl {FACILITATOR_URL}/supported
API docs: {FACILITATOR_URL}/docs
Source: {GITHUB_URL}</pre>
</div>

<div class="section">
<h2>Quick Test</h2>
<pre>curl {FACILITATOR_URL}/supported | python3 -m json.tool</pre>
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

LANDING_JSON = {
    "name": "x402 TON Facilitator",
    "description": "Verify and settle x402 payments on TON blockchain (USDT via gasless relay)",
    "version": "0.1.0",
    "facilitator_url": FACILITATOR_URL,
    "networks": ["tvm:-239", "tvm:-3"],
    "scheme": "exact",
    "asset": "0:b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe",
    "asset_symbol": "USDT",
    "endpoints": {
        "supported": "GET /supported",
        "verify": "POST /verify",
        "settle": "POST /settle",
        "health": "GET /health",
        "docs": "GET /docs",
    },
    "source": GITHUB_URL,
    "x402_spec": "https://github.com/coinbase/x402",
    "ton_spec_pr": "https://github.com/coinbase/x402/pull/1455",
}


# --- Endpoints ---


@app.get("/", include_in_schema=False)
async def landing(request: Request):
    """Landing page: HTML for browsers, JSON for agents."""
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return HTMLResponse(LANDING_HTML)
    return LANDING_JSON


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
