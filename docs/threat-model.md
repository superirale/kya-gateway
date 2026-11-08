# Threat model

Scope: the KYA API, the demo merchant agent, the shopping-agent SDK and the Telegraph adapter. **Out of scope for the hackathon:** real consumer identity proofing, real card or bank payments, and production key management (HSM/KMS).

## Trust boundaries

- **An agent signature proves key control, nothing more.** It is not the operator's legal identity, and not consumer consent on its own.
- **Consumer consent** is represented by a delegation signed by KYA's issuer key after a **demo** login. In production this must be replaced by real consumer authentication (OIDC/passkeys) and, ideally, consumer-held keys.
- **Telegraph intelligence** is an untrusted third-party input to risk decisioning. It is not a source of consent truth.
- **The merchant** is authenticated by API key and may only verify intents addressed to itself.

## Threats and mitigations

| Threat | Mitigation | Where / test |
|---|---|---|
| Forged purchase intent | Ed25519 verification against the registered key over a domain-separated canonical message | `service.Verify`; `TestTamperedSignatureDenied`, `TestWrongKeyDenied` |
| Canonicalization ambiguity (duplicate keys, floats, whitespace, unicode escapes) | Signatures cover server-recomputed canonical JSON. Duplicate keys are rejected (400), unknown fields rejected (422), integers only, non-canonical timestamps rejected. Cross-language vectors. | `internal/canonical`; `TestStrictDecoding`, `TestSchemaValidation`, `testdata/signing-vectors.json` |
| Cross-protocol signature reuse | Distinct signing domains for challenge, rotation, delegation and intent | `canonical.Domain*` |
| Nonce replay, including concurrent replay | Atomic unique `(agent_id, nonce)` and `intent_id` in PostgreSQL. 409 / `NONCE_REPLAY` | `TestReplayRejected`, `TestConcurrentReplayAtMostOne`, storage conformance |
| Nonce burning by a third party | The nonce is recorded only after the signature verifies | `service.Verify` ordering |
| Stale or old intents | ±5-minute timestamp window | `TestTimestampWindow` |
| Over-limit, expired, revoked, wrong-merchant, wrong-action or wrong-category use | Full delegation check before any spend | `delegation.Check`; matrix tests |
| Delegation tampering in the DB | The issuer signature is re-verified on every use, and stored claims must equal the signed bytes | `TestSignatureBindsClaims` |
| Revocation race | Revocation is checked at verification time from the DB. A purchase verified before revocation completes is accepted; that window is inherent and short | — |
| Parallel cumulative overspend | Row lock plus reservation sum inside one transaction | `TestParallelCumulativeBudget`, storage conformance |
| Confused deputy / merchant spoofing | The authenticated merchant must equal the body's `merchant_id` (403). Cross-merchant reads return 404. The signed intent binds the merchant. | `TestConfusedDeputyForbidden`, `TestEndToEndHTTP` |
| Cart substitution | The signed `cart_digest` is recomputed by the merchant from its own cart; mismatches are rejected before KYA is called | `apps/merchant-demo` |
| Registration with a key the caller does not hold | Single-use, expiring challenge signed by that key; the challenge binds the public key | `TestRegistrationRejectsBadProof` |
| Stale or compromised agent key | Rotation requires signatures from both the old and new key under an optimistic version check. Admin disable. | `TestKeyRotation`, `TestDisabledAgentDenied` |
| Fraudulent receipt strings | `SETTLED` requires both a recomputed signal hash and an on-chain USDC Transfer from our wallet to payTo. Otherwise `UNVERIFIED`, and the policy fails closed. | `TestX402VerifyEvidence`, `TestUnverifiableReceiptReview` |
| Prompt-injected provider output | Only an uppercase enum level and a finite, bounded numeric score are read. Free text is stored truncated and rendered as escaped text only. | `extractRisk`; `TestPromptInjectionTreatedAsData` |
| Provider outage or timeout | Fail closed (REVIEW, or DENY under strict policy). Fail-open configuration is impossible. No receipt is fabricated. | `TestTelegraphTimeoutFailsClosed`, `TestFailOpenConfigImpossible`, `TestX402Unreachable` |
| Runaway network spend | Per-call price cap, daily cap (reservations count before commit), concurrency cap and asset allowlist, all checked before signing | `TestX402PriceCap`, `TestDailyBudget` |
| Duplicate paid calls | Unique idempotency key persisted before paying. Retries reuse the same EIP-3009 authorization, which settles once. | storage conformance `telegraph idempotency` |
| Simulated results passed off as real | `Simulated` flag on all evidence. Competition mode refuses the simulated adapter, and policy never ALLOWs on simulated evidence there. Labeled in the API, CLI and UI. | `TestSimulatedRejectedInStrictPolicy`, `config.Load` |
| PII leakage to the provider or chain | The provider sees only bucketed, pseudonymous features. No customer data is collected at all. | `TestSubjectHasNoIdentifiers` |
| Secret leakage in logs | Headers and bodies are never logged. The wallet `String()` prints only the address. The wallet key is cleared from config after parsing, and `_FILE` secret loading is supported. | `api.middleware`, `telegraph.Wallet` |
| Audit tampering | Hash chain plus an append-only trigger. Tamper-**evident**, not tamper-proof: a DB superuser can rewrite the chain. Anchoring the head hash externally is roadmap. | `TestAuditChainTamperEvident`, `/v1/audit/verify` |
| Brute force / abuse | Token-bucket rate limit per key or IP, 64 KiB body limit, server timeouts | `api.rateLimiter` |
| Browser exposure of the merchant key | The dashboard only reaches KYA's public and consumer routes. Merchant reads go through the merchant agent's server-side proxy. CORS allowlist and CSP. | `deploy/nginx.conf` |

## Known limitations (honest list)

- The demo consumer login is not identity proofing, and the issuer key signs on the consumer's behalf.
- The in-memory rate limiter is per-process. Use Redis or an edge limiter for multi-instance deployments.
- The x402 `PAYMENT-SIGNATURE` payload shape is not yet confirmed against the live facilitator (see `telegraph-integration.md`).
- The issuer seed, session secret and wallet key come from env vars or files. Production needs KMS/HSM and rotation.
- No TLS termination in the Compose stack. Deploy behind an HTTPS proxy.
