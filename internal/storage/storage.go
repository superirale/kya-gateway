// Package storage defines KYA persistence with PostgreSQL (source of truth)
// and in-memory (tests / offline demo) implementations. Both guarantee
// atomic nonce uniqueness, single-use challenges and atomic spend reservation.
package storage

import (
	"context"
	"errors"
	"time"

	"github.com/superirale/kya-gateway/internal/evidence"
	"github.com/superirale/kya-gateway/internal/model"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrConflict      = errors.New("conflict")
	ErrReplay        = errors.New("nonce or intent id already used")
	ErrLimitExceeded = errors.New("cumulative delegation limit exceeded")
	ErrExpired       = errors.New("expired")
)

type Store interface {
	Ping(ctx context.Context) error

	CreateChallenge(ctx context.Context, c model.Challenge) error
	// ConsumeChallenge atomically deletes and returns a challenge (single use).
	ConsumeChallenge(ctx context.Context, id string, now time.Time) (model.Challenge, error)

	CreateAgent(ctx context.Context, a *model.Agent) error
	GetAgent(ctx context.Context, agentID string) (model.Agent, error)
	// RotateAgentKey succeeds only if the current key version equals oldVersion.
	RotateAgentKey(ctx context.Context, agentID string, oldVersion int, newKey []byte) (model.Agent, error)
	SetAgentStatus(ctx context.Context, agentID string, s model.AgentStatus) (model.Agent, error)

	CreateDelegation(ctx context.Context, d model.Delegation) error
	GetDelegation(ctx context.Context, delegationID string) (model.Delegation, error)
	ListDelegations(ctx context.Context, consumerRef string) ([]model.Delegation, error)
	RevokeDelegation(ctx context.Context, delegationID, consumerRef string, at time.Time) (model.Delegation, error)

	// RecordIntent inserts the intent; ErrReplay if (agent_id, nonce) or intent_id exists.
	RecordIntent(ctx context.Context, r *model.IntentRecord) error
	// ReserveSpend atomically reserves amount against a cumulative limit (nil = no cumulative limit).
	ReserveSpend(ctx context.Context, delegationID, intentRecordID string, amount int64, limit *int64) error
	ReleaseSpend(ctx context.Context, intentRecordID string) error

	GetTelegraphByIdempotency(ctx context.Context, key string) (*model.TelegraphRecord, error)
	SaveTelegraph(ctx context.Context, t *model.TelegraphRecord) error
	TelegraphSpendSince(ctx context.Context, since time.Time) (int64, error)

	SaveVerification(ctx context.Context, v *model.Verification) error
	GetVerification(ctx context.Context, id string) (model.Verification, error)
	ListVerifications(ctx context.Context, merchantID string, limit int) ([]model.Verification, error)

	// AppendAudit assigns Seq/PreviousHash/EventHash under a chain lock.
	AppendAudit(ctx context.Context, e model.AuditEvent) (model.AuditEvent, error)
	ListAudit(ctx context.Context, merchantID string, limit int) ([]model.AuditEvent, error)
	AllAudit(ctx context.Context) ([]model.AuditEvent, error)
}

func sealEvent(e model.AuditEvent, seq int64, prev string) model.AuditEvent {
	if e.ID == "" {
		e.ID = model.NewUUID()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	e.CreatedAt = e.CreatedAt.UTC().Truncate(time.Microsecond) // Postgres precision
	e.Seq, e.PreviousHash = seq, prev
	e.EventHash = evidence.EventHash(e)
	return e
}

// ComputeStats aggregates operations metrics from recent verifications.
func ComputeStats(vs []model.Verification) model.Stats {
	s := model.Stats{ByDecision: map[string]int64{}, ByReason: map[string]int64{}}
	var latSum, latN int64
	for _, v := range vs {
		s.Total++
		s.ByDecision[string(v.Decision)]++
		for _, r := range v.ReasonCodes {
			s.ByReason[r]++
		}
		if !v.TelegraphCalled {
			if v.Decision == model.Deny {
				s.RejectedBeforeSpend++
			}
			continue
		}
		t := v.Telegraph
		if t == nil {
			continue
		}
		s.TelegraphCalls++
		if t.ErrorCode != nil {
			s.TelegraphErrors++
		}
		if t.SettlementStatus == model.EvidenceSettled {
			s.TelegraphSettled++
		}
		if t.PriceMinor != nil && !t.Simulated {
			s.TelegraphSpendMinor += *t.PriceMinor
		}
		if t.LatencyMs != nil {
			latSum += int64(*t.LatencyMs)
			latN++
		}
	}
	if latN > 0 {
		s.AvgTelegraphLatency = float64(latSum) / float64(latN)
	}
	return s
}
