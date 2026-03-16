# x402 TON Facilitator

Verifies and settles [x402](https://github.com/coinbase/x402) payments on TON blockchain using **self-relay gas sponsorship**.

**Live:** https://ton-facilitator.okhlopkov.com
**Spec PR:** [coinbase/x402#1455](https://github.com/coinbase/x402/pull/1455)

## Architecture: Self-Relay

The facilitator acts as both **verifier** and **gas sponsor**. Like EVM's EIP-3009 flow, the client only signs — all blockchain interaction happens in the facilitator.

| Actor | Blockchain calls | What they do |
|-------|-----------------|--------------|
| **Client** (buyer) | **0** | Call `/prepare` → sign → send header |
| **Merchant** (server) | **0** | Express middleware → HTTP calls to facilitator |
| **Facilitator** | All | seqno lookup, verification, gas sponsorship, broadcast |

### How it compares

| | EVM (EIP-3009) | Solana (SVM) | **TON (self-relay)** |
|---|---|---|---|
| Client blockchain calls | 0 | 3 (mint, ATA, blockhash) | **0** |
| Client signs | EIP-712 typed data | Full Solana tx | W5 internal_signed |
| Facilitator pays gas | Yes (ETH) | Yes (SOL, as fee payer) | **Yes (TON)** |
| Facilitator signs tx | No | Yes (co-signs) | No (wraps user's signed body) |

### Payment Flow

```
Client              Merchant              Facilitator              TON
  |                    |                      |                      |
  |--- GET /resource -->|                     |                      |
  |<-- 402 + requirements|                    |                      |
  |                    |                      |                      |
  |--- POST /prepare ----------------------->| (queries seqno)      |
  |<-- {seqno, messages} --------------------|                      |
  |                    |                      |                      |
  | [sign locally]     |                      |                      |
  |                    |                      |                      |
  |--- GET /resource + X-PAYMENT ----------->|                      |
  |                    |--- POST /verify ---->| (checks sig, amount) |
  |                    |<-- is_valid ---------|                      |
  |                    |--- POST /settle ---->|                      |
  |                    |                      |--- internal msg ---->|
  |                    |                      |    (0.15 TON gas)    |
  |                    |<-- tx_hash ----------|<--- confirmed -------|
  |<-- 200 + data -----|                      |                      |
```

### How Self-Relay Works (W5 internal_signed)

1. Client signs a W5 `internal_signed` message (opcode `0x73696e74`) containing one jetton transfer
2. Facilitator receives the signed BoC, verifies signature + payment intent
3. Facilitator wraps the signed body in an **internal message** from its own wallet to the user's W5 wallet
4. Facilitator attaches 0.15 TON for gas and broadcasts
5. User's W5 wallet verifies the signature and executes the jetton transfer
6. Merchant receives USDT, user never needed TON for gas

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/prepare` | Get seqno + messages for client signing |
| POST | `/verify` | Verify payment payload (**required**) |
| POST | `/settle` | Settle on-chain via self-relay (idempotent) |
| GET | `/supported` | List supported payment kinds |
| GET | `/health` | Service health + facilitator wallet balance |

## Quick Start

```bash
git clone https://github.com/ohld/x402-ton-facilitator.git
cd x402-ton-facilitator
pip install -e ".[dev]"

cp .env.example .env
# Set TONAPI_KEY and FACILITATOR_PRIVATE_KEY

uvicorn facilitator.main:app --port 8402

# Tests
pytest tests/ -v
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TONAPI_KEY` | Recommended | TONAPI key for higher rate limits |
| `FACILITATOR_PRIVATE_KEY` | For settlement | Hex-encoded Ed25519 seed (32 bytes = 64 hex chars) |
| `GAS_AMOUNT` | No | nanoTON per relay (default: 150000000 = 0.15 TON) |
| `TESTNET` | No | Set to `true` for testnet |
| `PORT` | No | Server port (default: 8402) |

### Gas Wallet Funding

The facilitator wallet needs TON for gas sponsorship:
- Each payment costs ~0.05 TON in gas
- Start with **10 TON** (~200 payments)
- Monitor balance via `/health` endpoint

## Verification Rules

Every payment goes through 5 checks:

1. **Protocol** — scheme is `exact`, network is `tvm:-239` or `tvm:-3`
2. **Signature** — Ed25519 verification of the W5 signed BoC (supports both external and internal_signed formats)
3. **Payment intent** — exactly 1 jetton transfer, amount/destination/asset match, destination verified against on-chain jetton wallet
4. **Replay protection** — seqno vs on-chain, validUntil range, BoC hash dedup
5. **Simulation** — pre-simulation check (optional, off by default)

## Project Structure

```
tvm_core/           Pure TON logic (zero x402 dependency)
├── self_relay.py   Self-relay: prepare + relay via internal_signed
├── jetton.py       Build TEP-74 jetton transfer payloads
├── verify.py       5 verification rules
├── signing.py      W5R1 signing (external + internal formats)
├── boc.py          BoC parser (handles both W5 body formats)
├── ed25519.py      Ed25519 signature verification
├── providers.py    Abstract blockchain provider interface
├── tonapi.py       TONAPI implementation (reads + broadcast)
├── address.py      Address normalization
├── state.py        Payment state machine
├── types.py        Pydantic models
└── constants.py    Network IDs, opcodes, defaults

x402_tvm/           x402 SDK adapter layer
├── config.py       Facilitator + client config
└── exact/
    ├── facilitator.py  prepare/verify/settle orchestration
    ├── client.py       Client SDK (calls /prepare, signs, returns payload)
    └── server.py       Server SDK (price parsing, requirements)

facilitator/        FastAPI HTTP service
├── main.py         Endpoints + landing page
├── config.py       Environment variables
└── state.py        Singleton instances
```

## Related

- [x402 Protocol](https://github.com/coinbase/x402) — HTTP 402 payment standard
- [TON spec PR #1455](https://github.com/coinbase/x402/pull/1455) — TVM network support proposal
- [x402-ton-poc](https://github.com/ohld/x402-ton-poc) — TypeScript proof of concept
- [TEP-74](https://github.com/ton-blockchain/TEPs/blob/master/text/0074-jettons-standard.md) — Jetton transfer standard
- [W5 Specification](https://github.com/tonkeeper/w5) — Wallet v5 with internal_signed

## License

Apache 2.0
