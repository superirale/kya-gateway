# Commercial summary (draft)

> Draft for the submission form. Statements about the market are **hypotheses** to test, not results. Fill in the bracketed items with observed evidence before submitting.

**1. Who is the customer?**
Merchant platforms, marketplaces and agent-commerce gateways that receive checkout requests from AI shopping agents. Their risk or payments teams need to tell customer-authorized agents from abusive automation before money moves.

**2. What problem does it solve, and why now?**
Merchants can see bot traffic but cannot verify that a specific agent (a) controls a registered key, (b) holds a current, narrowly scoped consumer delegation, and (c) is making a transaction within budget and at acceptable risk. KYA returns one explainable ALLOW / REVIEW / DENY with stable reason codes, and blocks replayed, expired, revoked and over-limit requests before any paid risk check.

**3. How does it make money?** *(hypothesis)*
A free developer tier, then per-verification metering for merchant pilots. Telegraph intelligence is a separately tracked pass-through variable cost. Observed testnet price: $0.01 per `FRAUD_RISK_GENERAL` call. Requests rejected locally cost nothing; the demo shows [X]% rejected before spend. Enterprise add-ons: policy controls and audit retention.

**4. What evidence of demand exists?**
[Number] potential integrators interviewed; [summary of what they said about latency, evidence and pricing]. [Independent developer test: who, what they ran, with consent.] Do not count self-generated testnet transactions as adoption.

**5. What is next?**
A pilot merchant SDK; real consumer authentication (OIDC/passkeys) and consumer-held delegation keys; payment-processor and SCA interoperability; revocation federation; multi-provider risk routing; external anchoring of the audit-chain head.

---

**One-liner:** KYA Gateway lets merchant agents verify a shopping agent's cryptographic identity, consumer spending authority and transaction risk before checkout, using paid, verifiable intelligence from Telegraph.

**Real:** signed agent requests, delegation and replay enforcement, the policy engine, and (in x402 mode) the Telegraph testnet purchase and receipt verification.
**Simulated:** consumer identity proofing, merchandise payment and fulfilment.
