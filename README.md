# KYA Gateway

Merchant-side trust and authorization for autonomous commerce, built for Telegraph Hackathon Season II (Apps & Agents · Mission 07 Consumer Platform).

KYA verifies three things before a merchant accepts an agent's checkout:

- the shopping agent **controls a registered Ed25519 key**;
- it holds a **short-lived, narrowly scoped consumer delegation**;
- the transaction is **within policy**.

For eligible requests it then **buys risk intelligence through Telegraph** (x402 on Sepolia) and verifies the receipt. It returns an explainable `ALLOW` / `REVIEW` / `DENY` with stable reason codes and a hash-chained evidence trail.

> A cryptographic identity proves key control, not real-world identity or payment authorization. Telegraph's result is a risk input, not proof of consent. Merchandise checkout in this demo is **simulated**.

PRD: [docs/KYA_Gateway_Telegraph_Hackathon_PRD.md](docs/KYA_Gateway_Telegraph_Hackathon_PRD.md)

## Quick start

```bash
cp .env.example .env
podman-compose up --build         # dashboard http://localhost:5173 (docker compose also works)
```

Or natively (Go 1.25+, Node 22+):

```bash
npm install
go run ./apps/api                  # :8080 (in-memory store unless DATABASE_URL is set)
go run ./apps/merchant-demo        # :8081
npm run dev:dashboard              # :5173
npm run agent -- all               # CLI shopping agent runs every PRD scenario
```

Reviewers: see [docs/judge-runbook.md](docs/judge-runbook.md).

## Going live on Telegraph testnet

1. `make probe`: an **unpaid** check of the live 402 challenge (nothing is signed or spent).
2. Fund a dedicated **testnet-only** wallet with Sepolia test USDC, set `TELEGRAPH_WALLET_KEY_FILE`, and run `make probe-pay` for exactly one capped real purchase.
3. Run with `TELEGRAPH_ADAPTER=x402 KYA_MODE=competition` plus PostgreSQL and explicit secrets.

Details, observed evidence and open items are in [docs/telegraph-integration.md](docs/telegraph-integration.md).

## Repository

```text
apps/api              Go KYA service                 internal/canonical   deterministic JSON
apps/merchant-demo    merchant agent (simulated pay) internal/identity    Ed25519 challenge/rotation/intent
apps/shopping-agent   CLI signed-intent client       internal/delegation  issuer + delegation rules
apps/dashboard        Preact + TS + Vite UI          internal/policy      versioned decision engine
apps/telegraph-probe  integration spike tool         internal/telegraph   x402/EIP-3009 client, budget, simulated
sdk/typescript        @kya/sdk                       internal/service     verification pipeline
openapi/kya.yaml      API contract                   internal/storage     PostgreSQL + memory (shared conformance tests)
migrations/           SQL schema                     internal/evidence    evidence hashes, audit chain
```

Docs: [architecture](docs/architecture.md) · [threat model](docs/threat-model.md) · [Telegraph integration](docs/telegraph-integration.md) · [commercial summary](docs/commercial-summary.md)

## Integrate

**Shopping agent (TypeScript):**

```ts
import { AgentSigner, KyaClient, canonicalTimestamp, newId, newNonce } from '@kya/sdk';

const kya = new KyaClient('https://kya.example');
const agent = await AgentSigner.generate('agent_acme_001');   // keep agent.exportSecretKey() secret
await kya.registerAgent(agent, 'Acme shopping agent');        // proof-of-possession challenge

const signed = await agent.signIntent({
  merchantId: 'merchant_demo_001',
  delegationId,                                               // from the consumer's delegation
  intent: { intent_id: newId('pi_'), action: 'purchase', amount_minor: 35000, currency: 'USD',
            cart_digest, timestamp: canonicalTimestamp(), nonce: newNonce() },
});
// send `signed` to the merchant
```

**Merchant (server-side):**

```ts
import { KyaMerchantClient } from '@kya/sdk';
const kyaMerchant = new KyaMerchantClient('https://kya.example', process.env.KYA_MERCHANT_KEY!);
const v = await kyaMerchant.verify(signed);
if (v.decision === 'ALLOW') { /* take payment */ } else if (v.decision === 'REVIEW') { /* hold */ } else { /* reject: v.reason_codes */ }
```

Or call `POST /v1/verify-transactions` directly (see [openapi/kya.yaml](openapi/kya.yaml)). Signing is Ed25519 over `"KYA-PURCHASE-INTENT-V1\n" + canonical_json({agent_id, merchant_id, delegation_id, intent})`. Byte-exact test vectors are in `testdata/signing-vectors.json`.

## Tests

```bash
make test        # go vet + Go tests + SDK tests (cross-language vectors) + typecheck
make test-pg     # storage atomicity against PostgreSQL (needs KYA_TEST_DATABASE_URL)
make cover       # coverage of authorization/decision packages (currently 85%)
```

Every row of PRD §16's testing matrix has an automated test in `internal/service/verify_test.go`, including concurrent replay, parallel cumulative-budget exhaustion and prompt-injected provider output.
