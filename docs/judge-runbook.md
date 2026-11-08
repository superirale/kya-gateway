# Reviewer runbook

You can reproduce every decision in about 5 minutes. Everything runs locally; no account is needed.

## Option A — Podman (recommended; Docker also works)

```bash
cp .env.example .env
podman machine init        # macOS/Windows, first time only
podman machine start       # macOS/Windows, once per boot
podman-compose up --build  # or: docker compose up --build
```

Open the dashboard at http://localhost:5173. In **Scenarios**, click **Run all**, then use **inspect** on any result.

## Option B — native (Go 1.25+, Node 22+, optional PostgreSQL 15+)

```bash
npm install
# terminal 1 — KYA API (omit DATABASE_URL to use the in-memory store)
DATABASE_URL=postgres://user@localhost:5432/kya?sslmode=disable go run ./apps/api
# terminal 2 — merchant agent
go run ./apps/merchant-demo
# terminal 3 — dashboard (http://localhost:5173)
npm run dev:dashboard
# or run every scenario from the CLI shopping agent:
npm run agent -- all
```

## What to look for

| Scenario | Expected | Paid intelligence call? |
|---|---|---|
| Approved purchase ($350 / $500) | ALLOW | yes |
| Over budget ($650 / $500) | DENY `AMOUNT_EXCEEDS_DELEGATION` | **no** |
| High-risk intelligence | REVIEW `RISK_ELEVATED_REVIEW` | yes |
| Revoked delegation | DENY `DELEGATION_REVOKED` | **no** |
| Nonce replay | ALLOW, then DENY `NONCE_REPLAY` (HTTP 409) | first only |
| Tampered signature | DENY `INVALID_AGENT_SIGNATURE` | **no** |
| Provider unavailable | REVIEW `RISK_INTELLIGENCE_UNAVAILABLE`, no receipt | attempted |
| Expired delegation | DENY `DELEGATION_EXPIRED` | **no** |
| Wrong merchant | DENY `MERCHANT_NOT_ALLOWED` | **no** |

In the **Evidence** tab, check:

- the verification timeline;
- the evidence hash, recomputed server-side ("recomputed ✓");
- the Telegraph request ID, receipt and transaction link (only when actually returned);
- the provider result, shown as untrusted data.

In the **Operations** tab, check the audit chain status ("intact") and the share of requests denied before any spend.

## Real vs simulated

The status bar always shows which mode you are in.

- **Intelligence SIMULATED** (default `.env`): no Telegraph purchase happens. Evidence is labeled `SIMULATED`, has no receipt, tx or cost, and the high-risk and outage scenarios are driven locally.
- **Telegraph LIVE** (`TELEGRAPH_ADAPTER=x402`, funded testnet wallet; see `docs/telegraph-integration.md`): eligible requests buy `FRAUD_RISK_GENERAL` on Sepolia for about $0.01 each, under a per-call cap of $0.05 and a daily cap of $2.00. Locally denied requests never spend.
- Merchandise checkout is **always simulated**. Consumers and agents are synthetic.

## Try your own input

```bash
# Register your own agent key and buy through the merchant from code: see README "Integrate".
curl -s localhost:8080/v1/public/status | jq
```

## Tests

```bash
make test                                   # Go + TypeScript unit/integration tests
KYA_TEST_DATABASE_URL=postgres://… make test-pg   # storage atomicity against PostgreSQL
make cover                                  # critical decision-logic coverage
```
