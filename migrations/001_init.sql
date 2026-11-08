-- KYA Gateway schema v1. Applied automatically by the API at startup.

CREATE TABLE IF NOT EXISTS agent_challenges (
    challenge_id TEXT PRIMARY KEY,
    agent_id     TEXT NOT NULL,
    challenge    TEXT NOT NULL,
    purpose      TEXT NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
    id              UUID PRIMARY KEY,
    agent_id        TEXT NOT NULL UNIQUE,
    developer_label TEXT NOT NULL,
    public_key      BYTEA NOT NULL,
    key_version     INT NOT NULL DEFAULT 1,
    status          TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS delegations (
    id               UUID PRIMARY KEY,
    delegation_id    TEXT NOT NULL UNIQUE,
    agent_id         TEXT NOT NULL REFERENCES agents (agent_id),
    merchant_id      TEXT NOT NULL,
    consumer_ref     TEXT NOT NULL,
    allowed_actions  JSONB NOT NULL,
    max_amount_minor BIGINT NOT NULL CHECK (max_amount_minor > 0),
    cumulative_limit_minor BIGINT NULL,
    currency         CHAR(3) NOT NULL,
    issued_at        TIMESTAMPTZ NOT NULL,
    expires_at       TIMESTAMPTZ NOT NULL,
    revoked_at       TIMESTAMPTZ NULL,
    signed_payload   JSONB NOT NULL,
    signed_payload_text TEXT NOT NULL, -- exact canonical bytes that were signed
    signature        BYTEA NOT NULL
);
CREATE INDEX IF NOT EXISTS delegations_consumer_idx ON delegations (consumer_ref);

CREATE TABLE IF NOT EXISTS purchase_intents (
    id            UUID PRIMARY KEY,
    intent_id     TEXT NOT NULL UNIQUE,
    agent_id      TEXT NOT NULL REFERENCES agents (agent_id),
    delegation_id TEXT NOT NULL,
    merchant_id   TEXT NOT NULL,
    amount_minor  BIGINT NOT NULL,
    currency      CHAR(3) NOT NULL,
    cart_digest   TEXT NOT NULL,
    nonce         TEXT NOT NULL,
    intent_hash   TEXT NOT NULL,
    received_at   TIMESTAMPTZ NOT NULL,
    UNIQUE (agent_id, nonce)
);

CREATE TABLE IF NOT EXISTS spend_reservations (
    purchase_intent_id UUID PRIMARY KEY REFERENCES purchase_intents (id),
    delegation_id      TEXT NOT NULL REFERENCES delegations (delegation_id),
    amount_minor       BIGINT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS spend_reservations_dlg_idx ON spend_reservations (delegation_id);

CREATE TABLE IF NOT EXISTS telegraph_requests (
    id                 UUID PRIMARY KEY,
    purchase_intent_id UUID NOT NULL REFERENCES purchase_intents (id),
    idempotency_key    TEXT NOT NULL UNIQUE,
    intent_name        TEXT NOT NULL,
    network            TEXT NOT NULL,
    simulated          BOOLEAN NOT NULL DEFAULT false,
    request_id         TEXT NULL,
    provider_id        TEXT NULL,
    settlement_status  TEXT NOT NULL,
    receipt_id         TEXT NULL,
    tx_hash            TEXT NULL,
    explorer_url       TEXT NULL,
    price_minor        BIGINT NULL,
    price_currency     TEXT NULL,
    result_hash        TEXT NULL,
    latency_ms         INT NULL,
    error_code         TEXT NULL,
    record             JSONB NOT NULL, -- full observed record incl. untrusted result
    created_at         TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS verification_decisions (
    id                   TEXT PRIMARY KEY, -- ver_...
    purchase_intent_id   UUID NULL REFERENCES purchase_intents (id),
    telegraph_request_id UUID NULL REFERENCES telegraph_requests (id),
    merchant_id          TEXT NOT NULL,
    decision             TEXT NOT NULL CHECK (decision IN ('ALLOW', 'REVIEW', 'DENY')),
    reason_codes         JSONB NOT NULL,
    policy_version       TEXT NOT NULL,
    evidence_hash        TEXT NOT NULL,
    document             JSONB NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS verification_merchant_idx ON verification_decisions (merchant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_events (
    id            UUID PRIMARY KEY,
    seq           BIGINT NOT NULL UNIQUE,
    entity_type   TEXT NOT NULL,
    entity_id     TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    merchant_id   TEXT NOT NULL DEFAULT '',
    payload_hash  TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash    TEXT NOT NULL UNIQUE,
    created_at    TIMESTAMPTZ NOT NULL
);

-- Append-only: forbid UPDATE/DELETE on audit rows (tamper-evident, not tamper-proof).
CREATE OR REPLACE FUNCTION audit_events_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_events_no_mutation ON audit_events;
CREATE TRIGGER audit_events_no_mutation BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_append_only();
