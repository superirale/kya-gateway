package storage

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/superirale/kya-gateway/internal/evidence"
	"github.com/superirale/kya-gateway/internal/model"
	"github.com/superirale/kya-gateway/migrations"
)

type Postgres struct{ pool *pgxpool.Pool }

func OpenPostgres(ctx context.Context, url string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	p := &Postgres{pool: pool}
	if err := p.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return p, nil
}

func (p *Postgres) Close() { p.pool.Close() }

func (p *Postgres) migrate(ctx context.Context) error {
	if _, err := p.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	names, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, n := range names {
		var exists bool
		if err := p.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name=$1)`, n).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		sql, _ := migrations.FS.ReadFile(n)
		err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7340001)`); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES ($1) ON CONFLICT DO NOTHING`, n)
			return err
		})
		if err != nil {
			return fmt.Errorf("%s: %w", n, err)
		}
	}
	return nil
}

func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

func isUnique(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) CreateChallenge(ctx context.Context, c model.Challenge) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO agent_challenges (challenge_id, agent_id, challenge, purpose, expires_at) VALUES ($1,$2,$3,$4,$5)`,
		c.ChallengeID, c.AgentID, c.Challenge, c.Purpose, c.ExpiresAt)
	return err
}

func (p *Postgres) ConsumeChallenge(ctx context.Context, id string, now time.Time) (model.Challenge, error) {
	var c model.Challenge
	err := p.pool.QueryRow(ctx, `DELETE FROM agent_challenges WHERE challenge_id=$1 RETURNING challenge_id, agent_id, challenge, purpose, expires_at`, id).
		Scan(&c.ChallengeID, &c.AgentID, &c.Challenge, &c.Purpose, &c.ExpiresAt)
	if err != nil {
		return c, notFound(err)
	}
	if !now.Before(c.ExpiresAt) {
		return c, ErrExpired
	}
	return c, nil
}

const agentCols = `id, agent_id, developer_label, public_key, key_version, status, created_at, updated_at`

func scanAgent(row pgx.Row) (model.Agent, error) {
	var a model.Agent
	var st string
	err := row.Scan(&a.ID, &a.AgentID, &a.DeveloperLabel, &a.PublicKey, &a.KeyVersion, &st, &a.CreatedAt, &a.UpdatedAt)
	a.Status = model.AgentStatus(st)
	return a, notFound(err)
}

func (p *Postgres) CreateAgent(ctx context.Context, a *model.Agent) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO agents (`+agentCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		a.ID, a.AgentID, a.DeveloperLabel, a.PublicKey, a.KeyVersion, string(a.Status), a.CreatedAt, a.UpdatedAt)
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

func (p *Postgres) GetAgent(ctx context.Context, id string) (model.Agent, error) {
	return scanAgent(p.pool.QueryRow(ctx, `SELECT `+agentCols+` FROM agents WHERE agent_id=$1`, id))
}

func (p *Postgres) RotateAgentKey(ctx context.Context, id string, oldVersion int, key []byte) (model.Agent, error) {
	a, err := scanAgent(p.pool.QueryRow(ctx, `UPDATE agents SET public_key=$3, key_version=key_version+1, updated_at=now()
		WHERE agent_id=$1 AND key_version=$2 RETURNING `+agentCols, id, oldVersion, key))
	if errors.Is(err, ErrNotFound) {
		if _, e := p.GetAgent(ctx, id); e == nil {
			return a, ErrConflict
		}
	}
	return a, err
}

func (p *Postgres) SetAgentStatus(ctx context.Context, id string, s model.AgentStatus) (model.Agent, error) {
	return scanAgent(p.pool.QueryRow(ctx, `UPDATE agents SET status=$2, updated_at=now() WHERE agent_id=$1 RETURNING `+agentCols, id, string(s)))
}

func (p *Postgres) CreateDelegation(ctx context.Context, d model.Delegation) error {
	c := d.Claims
	actions, _ := json.Marshal(c.Actions)
	iat, err := time.Parse(time.RFC3339, c.IssuedAt)
	if err != nil {
		return err
	}
	exp, err := time.Parse(time.RFC3339, c.ExpiresAt)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `INSERT INTO delegations (id, delegation_id, agent_id, merchant_id, consumer_ref, allowed_actions,
		max_amount_minor, cumulative_limit_minor, currency, issued_at, expires_at, signed_payload, signed_payload_text, signature)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		d.ID, c.DelegationID, c.SubjectAgentID, c.MerchantID, c.ConsumerRef, actions, c.MaxAmountMinor, c.CumulativeLimitMinor,
		c.Currency, iat, exp, []byte(d.SignedPayload), string(d.SignedPayload), d.Signature)
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

const delegationSelect = `SELECT d.id, d.signed_payload_text, d.signature, d.revoked_at,
	COALESCE((SELECT SUM(amount_minor) FROM spend_reservations r WHERE r.delegation_id=d.delegation_id),0)
	FROM delegations d`

func scanDelegation(row pgx.Row) (model.Delegation, error) {
	var d model.Delegation
	var payload string
	if err := row.Scan(&d.ID, &payload, &d.Signature, &d.RevokedAt, &d.SpentMinor); err != nil {
		return d, notFound(err)
	}
	d.SignedPayload = json.RawMessage(payload)
	if err := json.Unmarshal(d.SignedPayload, &d.Claims); err != nil {
		return d, err
	}
	d.SignatureB64 = b64(d.Signature)
	return d, nil
}

func (p *Postgres) GetDelegation(ctx context.Context, id string) (model.Delegation, error) {
	return scanDelegation(p.pool.QueryRow(ctx, delegationSelect+` WHERE d.delegation_id=$1`, id))
}

func (p *Postgres) ListDelegations(ctx context.Context, consumerRef string) ([]model.Delegation, error) {
	rows, err := p.pool.Query(ctx, delegationSelect+` WHERE d.consumer_ref=$1 ORDER BY d.issued_at DESC LIMIT 200`, consumerRef)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Delegation
	for rows.Next() {
		d, err := scanDelegation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (p *Postgres) RevokeDelegation(ctx context.Context, id, consumerRef string, at time.Time) (model.Delegation, error) {
	tag, err := p.pool.Exec(ctx, `UPDATE delegations SET revoked_at=COALESCE(revoked_at,$3) WHERE delegation_id=$1 AND consumer_ref=$2`, id, consumerRef, at)
	if err != nil {
		return model.Delegation{}, err
	}
	if tag.RowsAffected() == 0 {
		return model.Delegation{}, ErrNotFound
	}
	return p.GetDelegation(ctx, id)
}

func (p *Postgres) RecordIntent(ctx context.Context, r *model.IntentRecord) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO purchase_intents (id, intent_id, agent_id, delegation_id, merchant_id, amount_minor, currency,
		cart_digest, nonce, intent_hash, received_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		r.ID, r.IntentID, r.AgentID, r.DelegationID, r.MerchantID, r.AmountMinor, r.Currency, r.CartDigest, r.Nonce, r.IntentHash, r.ReceivedAt)
	if isUnique(err) {
		return ErrReplay
	}
	return err
}

// ReserveSpend locks the delegation row so concurrent reservations serialize.
func (p *Postgres) ReserveSpend(ctx context.Context, delegationID, intentRecordID string, amount int64, limit *int64) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		var one int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM delegations WHERE delegation_id=$1 FOR UPDATE`, delegationID).Scan(&one); err != nil {
			return notFound(err)
		}
		var spent int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(SUM(amount_minor),0) FROM spend_reservations WHERE delegation_id=$1`, delegationID).Scan(&spent); err != nil {
			return err
		}
		if limit != nil && spent+amount > *limit {
			return ErrLimitExceeded
		}
		_, err := tx.Exec(ctx, `INSERT INTO spend_reservations (purchase_intent_id, delegation_id, amount_minor) VALUES ($1,$2,$3)`, intentRecordID, delegationID, amount)
		return err
	})
}

func (p *Postgres) ReleaseSpend(ctx context.Context, intentRecordID string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM spend_reservations WHERE purchase_intent_id=$1`, intentRecordID)
	return err
}

func (p *Postgres) GetTelegraphByIdempotency(ctx context.Context, key string) (*model.TelegraphRecord, error) {
	var raw []byte
	if err := p.pool.QueryRow(ctx, `SELECT record FROM telegraph_requests WHERE idempotency_key=$1`, key).Scan(&raw); err != nil {
		return nil, notFound(err)
	}
	var t model.TelegraphRecord
	return &t, json.Unmarshal(raw, &t)
}

func (p *Postgres) SaveTelegraph(ctx context.Context, t *model.TelegraphRecord) error {
	rec, _ := json.Marshal(t)
	_, err := p.pool.Exec(ctx, `INSERT INTO telegraph_requests (id, purchase_intent_id, idempotency_key, intent_name, network, simulated,
		request_id, provider_id, settlement_status, receipt_id, tx_hash, explorer_url, price_minor, price_currency, result_hash,
		latency_ms, error_code, record, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''),$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
		ON CONFLICT (id) DO UPDATE SET request_id=EXCLUDED.request_id, provider_id=EXCLUDED.provider_id,
		settlement_status=EXCLUDED.settlement_status, receipt_id=EXCLUDED.receipt_id, tx_hash=EXCLUDED.tx_hash,
		explorer_url=EXCLUDED.explorer_url, price_minor=EXCLUDED.price_minor, price_currency=EXCLUDED.price_currency,
		result_hash=EXCLUDED.result_hash, latency_ms=EXCLUDED.latency_ms, error_code=EXCLUDED.error_code, record=EXCLUDED.record`,
		t.ID, t.PurchaseIntentID, t.IdempotencyKey, t.IntentName, t.Network, t.Simulated, t.RequestID, t.ProviderID,
		string(t.SettlementStatus), t.ReceiptID, t.TxHash, t.ExplorerURL, t.PriceMinor, t.PriceCurrency, t.ResultHash,
		t.LatencyMs, t.ErrorCode, rec, t.CreatedAt)
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

func (p *Postgres) TelegraphSpendSince(ctx context.Context, since time.Time) (int64, error) {
	var s int64
	err := p.pool.QueryRow(ctx, `SELECT COALESCE(SUM(price_minor),0) FROM telegraph_requests WHERE NOT simulated AND created_at >= $1`, since).Scan(&s)
	return s, err
}

func (p *Postgres) SaveVerification(ctx context.Context, v *model.Verification) error {
	doc, _ := json.Marshal(v)
	reasons, _ := json.Marshal(v.ReasonCodes)
	var tgID *string
	if v.Telegraph != nil {
		tgID = &v.Telegraph.ID
	}
	_, err := p.pool.Exec(ctx, `INSERT INTO verification_decisions (id, purchase_intent_id, telegraph_request_id, merchant_id, decision,
		reason_codes, policy_version, evidence_hash, document, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		v.ID, v.PurchaseIntentID, tgID, v.MerchantID, string(v.Decision), reasons, v.PolicyVersion, v.EvidenceHash, doc, v.CreatedAt)
	return err
}

func (p *Postgres) GetVerification(ctx context.Context, id string) (model.Verification, error) {
	var raw []byte
	var v model.Verification
	if err := p.pool.QueryRow(ctx, `SELECT document FROM verification_decisions WHERE id=$1`, id).Scan(&raw); err != nil {
		return v, notFound(err)
	}
	return v, json.Unmarshal(raw, &v)
}

func (p *Postgres) ListVerifications(ctx context.Context, merchantID string, limit int) ([]model.Verification, error) {
	if limit <= 0 || limit > 5000 {
		limit = 5000
	}
	rows, err := p.pool.Query(ctx, `SELECT document FROM verification_decisions WHERE ($1='' OR merchant_id=$1) ORDER BY created_at DESC LIMIT $2`, merchantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Verification
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var v model.Verification
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (p *Postgres) AppendAudit(ctx context.Context, e model.AuditEvent) (model.AuditEvent, error) {
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7340002)`); err != nil {
			return err
		}
		var seq int64
		prev := evidence.GenesisHash
		err := tx.QueryRow(ctx, `SELECT seq, event_hash FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&seq, &prev)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		e = sealEvent(e, seq+1, prev)
		_, err = tx.Exec(ctx, `INSERT INTO audit_events (id, seq, entity_type, entity_id, event_type, merchant_id, payload_hash, previous_hash, event_hash, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, e.ID, e.Seq, e.EntityType, e.EntityID, e.EventType, e.MerchantID, e.PayloadHash, e.PreviousHash, e.EventHash, e.CreatedAt)
		return err
	})
	return e, err
}

func (p *Postgres) queryAudit(ctx context.Context, sql string, args ...any) ([]model.AuditEvent, error) {
	rows, err := p.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AuditEvent
	for rows.Next() {
		var e model.AuditEvent
		if err := rows.Scan(&e.ID, &e.Seq, &e.EntityType, &e.EntityID, &e.EventType, &e.MerchantID, &e.PayloadHash, &e.PreviousHash, &e.EventHash, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.CreatedAt = e.CreatedAt.UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

const auditCols = `id, seq, entity_type, entity_id, event_type, merchant_id, payload_hash, previous_hash, event_hash, created_at`

func (p *Postgres) ListAudit(ctx context.Context, merchantID string, limit int) ([]model.AuditEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	return p.queryAudit(ctx, `SELECT `+auditCols+` FROM audit_events WHERE ($1='' OR merchant_id=$1) ORDER BY seq DESC LIMIT $2`, merchantID, limit)
}

func (p *Postgres) AllAudit(ctx context.Context) ([]model.AuditEvent, error) {
	return p.queryAudit(ctx, `SELECT `+auditCols+` FROM audit_events ORDER BY seq ASC`)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
