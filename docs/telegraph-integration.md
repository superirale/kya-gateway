# Telegraph integration

Status as of **7 November 2026**. This document separates what was **observed on the live network**, what is **documented but not yet exercised**, and what is **assumed**. Update it as evidence arrives. Never paste a key here.

## Selected intent

| Field | Value | Source |
|---|---|---|
| Intent | `FRAUD_RISK_GENERAL` (class `judgment`) | `GET https://devnode.telegraphprotocol.com/engine/v1/intents/FRAUD_RISK_GENERAL` |
| Request params | `subject` (string, required): "Entity, payment or account to assess" | same |
| Response fields | `risk_level` enum `LOW\|MEDIUM\|HIGH\|CRITICAL` (on-chain); `risk_score` number 0–1, 6 decimals; `signals` list; `summary` string | same |
| Network | Ethereum Sepolia, CAIP-2 `eip155:11155111` | 402 challenge (observed) |
| Payment asset | Test USDC `0xcc194e1a843B658526D0D5C431f670028582Ae17`, 6 decimals | 402 challenge (observed) |
| Pay-to | `0x3624EB012B5E998BB57B6bE6C9Cfc9c4bc5eb99b` (read from each challenge, never hard-coded) | 402 challenge (observed) |
| Observed price | `10000` micro-USDC = **$0.01** per call | 402 challenge (observed) |
| Alternative | `FRAUD_DETECTION_GENERAL` (`verdict` enum + `risk_score`). Thresholds already calibrated in `policy.DefaultConfig()` | intents API |

Why this intent: it is the only fraud/transaction-risk intent whose input/output schema we have confirmed. `TRANSACTION_RISK_GENERAL` exists in the catalogue but its schema has not been read yet. If it proves a better fit, set `TELEGRAPH_INTENT` and add thresholds for it in `internal/policy` (uncalibrated intents fail closed with `RISK_RESULT_UNRECOGNIZED`).

**What we send.** The `subject` is built from pseudonymous, bucketed features only: a hashed merchant ref, amount bucket, category, key-age and delegation-age buckets, and share of the limit used. See `telegraph.RiskRequest.Subject()`; a test asserts that no agent, merchant or delegation identifiers leak.

## Flow implemented (`internal/telegraph/x402.go`)

1. `POST /engine/v1/ask` `{"intent":"FRAUD_RISK_GENERAL","params":{"subject":"…"}}` with no payment returns **402** and a `PAYMENT-REQUIRED` header (base64 JSON, `x402Version: 2`). Retried on 429/5xx; nothing is paid at this stage.
2. KYA picks the `accepts[]` entry with `scheme: "exact"` on the configured network and an **allowlisted asset**. It enforces the **per-call cap** (`TELEGRAPH_MAX_PRICE_MINOR`) and then the **daily cap and concurrency** (`DailyBudget`) before signing.
3. KYA signs an EIP-3009 `TransferWithAuthorization` using EIP-712: domain `{name, version}` from `extra`, `chainId` from the CAIP-2 network, `verifyingContract` = asset, a random 32-byte nonce, and `validBefore = now + maxTimeoutSeconds`.
4. The request is resent with `PAYMENT-SIGNATURE: base64({x402Version, resource?, accepted, payload:{signature, authorization}})`. Retries reuse the **same** signed authorization, which is idempotent because an EIP-3009 nonce can settle only once.
5. On 200, KYA parses `signal_hash`, `miner_id`, `miner_name`, `result`, `intent` (it must equal the requested intent, otherwise `TELEGRAPH_SCHEMA_MISMATCH`) and the `X-TELEGRAPH-RECEIPT` header (`receipt_hash`, `tx_hash`, `amount_uusdc`, `payer`). If the receipt has no tx hash, it falls back to `PAYMENT-RESPONSE`.
6. **Verification** (`VerifyEvidence`): KYA fetches `GET /engine/v1/signal/{signal_hash}` and recomputes the keccak256 hash over the returned payload. With a Sepolia RPC configured, it also confirms on chain that the tx succeeded and contains a USDC `Transfer` from our wallet to `payTo`. Evidence is `SETTLED` only when **both** checks pass; otherwise it is `UNVERIFIED` with a note, and the policy fails closed (`TELEGRAPH_SETTLEMENT_UNVERIFIED`).

Persistence and idempotency: before paying, KYA inserts a `telegraph_requests` row in state `REQUESTED` under a unique idempotency key, `tg:<intent_hash>`, so the same signed intent can never trigger two paid calls.

## Evidence log

### 2026-11-07 — unpaid challenge probe (observed)

`go run ./apps/telegraph-probe` (unpaid; nothing signed or spent) against `https://devnode.telegraphprotocol.com`:

```json
{
  "http_status": 402,
  "x402_version": 2,
  "accepts": [
    { "scheme": "exact", "network": "eip155:11155111",
      "asset": "0xcc194e1a843B658526D0D5C431f670028582Ae17", "amount": "10000",
      "payTo": "0x3624EB012B5E998BB57B6bE6C9Cfc9c4bc5eb99b", "maxTimeoutSeconds": 60,
      "extra": { "name": "USD Coin", "version": "2" } },
    { "scheme": "escrow", "network": "eip155:11155111", "amount": "10000",
      "payTo": "0x3624eb012b5e998bb57b6be6c9cfc9c4bc5eb99b",
      "extra": { "signWith": "personal_sign (EIP-191)", "resource": "/v1/ask", "...": "…" } }
  ],
  "usable": true
}
```

The live challenge matches the parser. The `escrow` option is deliberately not used; it is a candidate future optimisation, since it avoids per-request settlement.

### 2026-11-08 — first real paid purchase (observed, SETTLED)

`make probe-pay` (one capped call) from testnet wallet `0x6b4209aC61638495187394898E73F8E0672b7aD2`:

| Field | Observed value |
|---|---|
| Request (`signal_hash`) | `0x65cbeac5138c72f916a8ce8d86c0c625772aabb89ec72b86a5e7eed19d3907bf` |
| Receipt (`receipt_hash`) | `0xadd3fea85ce722d0148943614357192f471b2fda1938c5ff74b27b400b87225d` |
| Settlement tx | [`0x735534905df6264b38b6858d1314f31c51b96f25639634b0a6a4208f36d5b858`](https://sepolia.etherscan.io/tx/0x735534905df6264b38b6858d1314f31c51b96f25639634b0a6a4208f36d5b858) |
| Price | `10000` micro-USDC ($0.01), rail `x402`, settlement `onchain`, chain `eip155:11155111` |
| Provider | `miner_id` 7431 "RiskWire Fraud Risk" (receipt `miner` 4416 is the on-chain registration id) |
| Latency | 16,946 ms |
| KYA verification | **SETTLED**: signal hash recomputed and matched; on-chain Transfer from payer to payTo confirmed |
| Result | `{"risk_level": null, "risk_score": null, "signals": null, "summary": "An assessment for this request could not be produced at this time because the language model could not be reached."}` |

Findings:

- The x402 v2 `PAYMENT-SIGNATURE` payload, the receipt field names and the signal-hash recipe are now **confirmed** on the live network.
- **A paid call can settle and still deliver no assessment.** KYA does not treat that as low risk: no recognized level or valid score means fail-closed `REVIEW` / `RISK_RESULT_UNRECOGNIZED`. The charge is real, so cost metrics must count paid-but-empty results.
- Latency of about 17 s is far above an interactive checkout budget. Track p95 and consider a pre-authorization flow.

### 2026-11-08 — miner routing finding and first structured result

Three more auto-routed calls all went to miner 7431 (RiskWire), an LLM-style miner. Two returned prose verdicts ("Low fraud risk…") in `summary` but `risk_level`/`risk_score` = null. One call returned `TELEGRAPH_PAYMENT_REJECTED`: the bare 402 was not charged, cause unknown, and it was not reproduced.

Most `FRAUD_RISK_GENERAL` miners are IP, BIN or URL lookup feeds, so a free-text `subject` describing a transaction is routed to the LLM miner. Calling `POST /engine/v1/ask/501` directly returned a structured result on the first attempt:

| Field | Observed value |
|---|---|
| Miner | 501 "Telegraph Sentinel Risk Intelligence" |
| Request (`signal_hash`) | `0x468814d00d368505a65c8ac92707b7161c911e8a989480f5cf83f0b9fe5df67d` |
| Receipt | `0xac5fa7caa5110b3829d67afdd988589c2aa952c6ebed3aad3688fed280b0e49e` |
| Settlement tx | [`0x8fa0a7154b1ef4acb257956e390669b09ee3e9e1089a3c8137e07eb3e7f911fe`](https://sepolia.etherscan.io/tx/0x8fa0a7154b1ef4acb257956e390669b09ee3e9e1089a3c8137e07eb3e7f911fe) |
| Price / latency | 10000 micro-USDC ($0.01) / 17,073 ms |
| Result | `{"risk_level":"LOW","risk_score":0.15,"signals":null,"summary":"Low fraud risk. Risk score: 15/100, confidence: 0.92. Clean profile without detected malicious indicators."}` |
| KYA verification | **SETTLED** (signal re-hash matched; on-chain Transfer confirmed) |
| Policy `hackathon-v1` | LOW → ALLOW; 0.15 < review threshold 0.60 → **ALLOW / RISK_ACCEPTABLE** |

Decision: pin `TELEGRAPH_MINER_ID=501` for the demo. Auto-routing remains the default when the variable is unset.

### 2026-11-08 — live end-to-end run (competition mode)

`KYA_MODE=competition`, `TELEGRAPH_ADAPTER=x402`, `TELEGRAPH_MINER_ID=501`, PostgreSQL, fresh secrets. CLI agent: `npm run agent -- allow over_limit replay`.

| Scenario | Decision | Telegraph | Evidence |
|---|---|---|---|
| $350 / $500 limit | **ALLOW** `RISK_ACCEPTABLE` | SETTLED, $0.01 | request `0x1c22c6b04c7764c91ee017808b924ef5173490d894aa27dd85734f3066bc3b1e`, [tx](https://sepolia.etherscan.io/tx/0x5ae2df3e21229ef94d2177bda388faafad6f39fa6bd37a6229da5d17d82a93bf) |
| $650 / $500 limit | **DENY** `AMOUNT_EXCEEDS_DELEGATION` | not called | — |
| Replay: first submission | **ALLOW** | SETTLED, $0.01 | request `0xe7a3bb9eab2f44e0f062a65a197a0c60a250d49470f170876f29c4d5603c4095`, [tx](https://sepolia.etherscan.io/tx/0x4ebd5d39d8bd417a30a3e7efd1bbe027b34f2483da27dc8ffc506d733cc6876b) |
| Replay: same signed request | **DENY** `NONCE_REPLAY` (HTTP 409) | not called | — |

Totals: 4 verifications, 2 paid calls, 2 settled and verified, 0 errors, spend 20000 micro-USDC ($0.02), 2 of 4 rejected before spend, average intelligence latency 13.3 s. Audit chain intact (8 events). Competition mode reported `accept_simulated: false` and started only with Postgres plus explicit secrets.

### Further paid runs

To repeat or extend the evidence:

1. Create a **dedicated testnet-only** wallet. Fund it with a little Sepolia ETH from a public faucet; this pays gas for the mint transaction only.
2. Put the key in a file outside the repo and set `TELEGRAPH_WALLET_KEY_FILE`. Run `make mint USDC=10`. The token contract is not verified on Etherscan, so the probe sends the permissionless `mint(address,uint256)` call itself. Check balances with `make balance`.
3. Run `make probe-pay`. It caps spend at exactly one call. Commit the JSON output here (it contains no secrets): `signal_hash`, `receipt_hash`, `tx_hash`, explorer link, `amount_uusdc` and the verification note.
4. Run the full stack with `TELEGRAPH_ADAPTER=x402` and `KYA_MODE=competition`, then run `npm run agent -- allow over_limit replay`. Record verification IDs and receipts here.

## Confirmed vs. assumed

| Item | Status |
|---|---|
| 402 challenge format, network, asset, amount, payTo, EIP-712 domain | **Observed** (probe above) |
| `FRAUD_RISK_GENERAL` schema | **Observed** (intents API) |
| EIP-3009 typehash, EIP-712 digest, secp256k1 signing, address derivation | **Tested** against the Circle FiatTokenV2 typehash and a known key→address vector |
| x402 v2 `PAYMENT-SIGNATURE` payload shape (`accepted` + `payload.authorization`) | **Observed**: accepted and settled 2026-11-08 |
| `X-TELEGRAPH-RECEIPT` field names | **Observed** 2026-11-08 |
| `/engine/v1/signal/{hash}` payload and hash recipe | **Observed**: recomputed hash matched 2026-11-08 |
| Miners always return an assessment | **False**: a settled call returned all-null fields (see above) |
| Receipts carry no per-receipt signature | Documented; verification therefore relies on signal re-hashing plus an on-chain Transfer check |
| `tx_hash` is not unique per call (facilitator batches) | Documented; the on-chain check matches on payer + payTo, not tx uniqueness |

If the live facilitator rejects the payment payload, the adapter returns `TELEGRAPH_PAYMENT_REJECTED`. Nothing is charged, and the decision fails closed. Fix the payload shape in `buildPayment` and add the observed format here.
