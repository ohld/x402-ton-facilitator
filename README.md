# x402 TON Facilitator

Verifies and settles [x402](https://github.com/coinbase/x402) payments on TON blockchain using USDT via TONAPI gasless relay.

**Live:** https://ton-facilitator.okhlopkov.com

**Spec PR:** [coinbase/x402#1455](https://github.com/coinbase/x402/pull/1455) — TVM (TON) network support

## Quick Start

```bash
# Clone
git clone https://github.com/ohld/x402-ton-facilitator.git
cd x402-ton-facilitator

# Install dependencies
pip install -e .

# Configure
cp .env.example .env
# Edit .env — set TONAPI_KEY (optional, increases rate limits)

# Run
uvicorn facilitator.main:app --host 0.0.0.0 --port 8402
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/supported` | Payment kinds this facilitator supports |
| `POST` | `/verify` | Verify a payment payload |
| `POST` | `/settle` | Settle a payment on-chain (idempotent) |
| `GET` | `/health` | Service health + provider connectivity |
| `GET` | `/docs` | OpenAPI interactive docs |

### Example: Check supported payments

```bash
curl https://ton-facilitator.okhlopkov.com/supported
```

```json
{
  "kinds": [
    {"x402Version": 2, "scheme": "exact", "network": "tvm:-239"},
    {"x402Version": 2, "scheme": "exact", "network": "tvm:-3"}
  ],
  "extensions": [],
  "signers": {}
}
```

## Architecture

3-layer design for clean upstream extraction:

```
tvm_core/          Pure TON verification logic (no x402 dependency)
├── constants.py   USDT master, W5 code hashes, CAIP-2 IDs
├── types.py       Pydantic models: TvmPaymentPayload, PaymentState, etc.
├── address.py     Address normalization (UQ/EQ <-> raw 0:hex)
├── boc.py         BoC parser: W5 body -> jetton_transfer extraction
├── ed25519.py     Signature verification, W5 code hash check
├── verify.py      6 verification rules (protocol, sig, intent, replay, relay, sim)
├── providers.py   Abstract TonProvider / TonSettler protocols
├── tonapi.py      TONAPI implementation of provider interface
└── state.py       Payment state machine (idempotent settlement)

x402_tvm/          Thin x402 SDK adapter (extractable for upstream PR)
└── exact/
    ├── facilitator.py   SchemeNetworkFacilitator: verify(), settle()
    ├── client.py        SchemeNetworkClient: create_payment_payload()
    ├── server.py        SchemeNetworkServer: parse_price(), enhance_requirements()
    └── register.py      register_exact_tvm_{client,server,facilitator}()

facilitator/       FastAPI HTTP service
├── main.py        4 endpoints + OpenAPI docs
├── config.py      Environment variables
└── state.py       App state singleton
```

## Verification Rules

Every payment goes through 6 checks:

1. **Protocol** — scheme is `exact`, network is `tvm:-239` or `tvm:-3`
2. **Signature** — Ed25519 verification of the W5R1 signed BoC
3. **Payment intent** — jetton transfer amount/destination/asset match, payTo verified against on-chain jetton wallet
4. **Replay protection** — seqno vs on-chain, validUntil range, BoC hash dedup
5. **Relay safety** — commission within bounds, relay address validated
6. **Simulation** — gasless pre-simulation (optional, off by default in MVP)

## Payment Flow

```
Client                    Resource Server              Facilitator
  |                            |                           |
  |-- GET /resource ---------->|                           |
  |<- 402 + PaymentRequired ---|                           |
  |                            |                           |
  | [build W5 jetton_transfer] |                           |
  | [sign with Ed25519]        |                           |
  |                            |                           |
  |-- GET /resource + X-PAYMENT header --->|               |
  |                            |-- POST /verify ---------->|
  |                            |<- {is_valid: true} -------|
  |                            |-- POST /settle ---------->|
  |                            |   [gasless/send to TONAPI]|
  |                            |<- {success, tx_hash} -----|
  |<- 200 + resource ----------|                           |
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `TONAPI_KEY` | *(empty)* | TONAPI bearer token (optional, increases rate limits) |
| `RELAY_ADDRESS` | *(empty)* | Expected gasless relay address |
| `MAX_RELAY_COMMISSION` | `500000` | Max commission in USDT nano (0.5 USDT) |
| `TESTNET` | `false` | Use testnet.tonapi.io |
| `SUPPORTED_NETWORKS` | `tvm:-239,tvm:-3` | Comma-separated CAIP-2 network IDs |
| `PORT` | `8402` | HTTP listen port |

## Docker

```bash
docker build -t ton-facilitator .
docker run -p 8402:8402 -e TONAPI_KEY=your_key ton-facilitator
```

## Integration with x402 Python SDK

```python
from x402_tvm.exact.register import register_exact_tvm_facilitator
from tvm_core.tonapi import TonapiProvider

provider = TonapiProvider(api_key="your_key")
register_exact_tvm_facilitator(facilitator, provider, provider, networks=["tvm:-239"])
```

## Related Links

- [x402 Protocol](https://github.com/coinbase/x402) — HTTP 402 payment standard
- [TON spec PR #1455](https://github.com/coinbase/x402/pull/1455) — TVM network support proposal
- [x402-ton-poc](https://github.com/ohld/x402-ton-poc) — TypeScript proof of concept
- [TONAPI Gasless](https://docs.tonconsole.com/tonapi/gasless) — Gasless transaction relay
- [TEP-74](https://github.com/ton-blockchain/TEPs/blob/master/text/0074-jettons-standard.md) — Jetton transfer standard

## License

Apache 2.0
