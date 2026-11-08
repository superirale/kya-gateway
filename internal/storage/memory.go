package storage

import (
	"context"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/superirale/kya-gateway/internal/evidence"
	"github.com/superirale/kya-gateway/internal/model"
)

// Memory is a mutex-guarded in-memory Store. Not durable.
type Memory struct {
	mu            sync.Mutex
	challenges    map[string]model.Challenge
	agents        map[string]model.Agent
	delegations   map[string]model.Delegation
	nonces        map[string]bool // agent_id|nonce
	intentIDs     map[string]bool
	reservations  map[string]reservation
	telegraph     map[string]*model.TelegraphRecord // by idempotency key
	verifications map[string]model.Verification
	audit         []model.AuditEvent
}

type reservation struct {
	delegationID string
	amount       int64
}

func NewMemory() *Memory {
	return &Memory{
		challenges: map[string]model.Challenge{}, agents: map[string]model.Agent{},
		delegations: map[string]model.Delegation{}, nonces: map[string]bool{}, intentIDs: map[string]bool{},
		reservations: map[string]reservation{}, telegraph: map[string]*model.TelegraphRecord{},
		verifications: map[string]model.Verification{},
	}
}

func (m *Memory) Ping(context.Context) error { return nil }

func (m *Memory) CreateChallenge(_ context.Context, c model.Challenge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.challenges[c.ChallengeID] = c
	return nil
}

func (m *Memory) ConsumeChallenge(_ context.Context, id string, now time.Time) (model.Challenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.challenges[id]
	if !ok {
		return c, ErrNotFound
	}
	delete(m.challenges, id)
	if !now.Before(c.ExpiresAt) {
		return c, ErrExpired
	}
	return c, nil
}

func (m *Memory) CreateAgent(_ context.Context, a *model.Agent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.agents[a.AgentID]; ok {
		return ErrConflict
	}
	m.agents[a.AgentID] = *a
	return nil
}

func (m *Memory) GetAgent(_ context.Context, id string) (model.Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.agents[id]
	if !ok {
		return a, ErrNotFound
	}
	return a, nil
}

func (m *Memory) RotateAgentKey(_ context.Context, id string, oldVersion int, key []byte) (model.Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.agents[id]
	if !ok {
		return a, ErrNotFound
	}
	if a.KeyVersion != oldVersion {
		return a, ErrConflict
	}
	a.PublicKey, a.KeyVersion, a.UpdatedAt = slices.Clone(key), a.KeyVersion+1, time.Now().UTC()
	m.agents[id] = a
	return a, nil
}

func (m *Memory) SetAgentStatus(_ context.Context, id string, s model.AgentStatus) (model.Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.agents[id]
	if !ok {
		return a, ErrNotFound
	}
	a.Status, a.UpdatedAt = s, time.Now().UTC()
	m.agents[id] = a
	return a, nil
}

func (m *Memory) CreateDelegation(_ context.Context, d model.Delegation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.delegations[d.Claims.DelegationID]; ok {
		return ErrConflict
	}
	m.delegations[d.Claims.DelegationID] = d
	return nil
}

func (m *Memory) spent(delegationID string) int64 {
	var s int64
	for _, r := range m.reservations {
		if r.delegationID == delegationID {
			s += r.amount
		}
	}
	return s
}

func (m *Memory) GetDelegation(_ context.Context, id string) (model.Delegation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.delegations[id]
	if !ok {
		return d, ErrNotFound
	}
	d.SpentMinor = m.spent(id)
	return d, nil
}

func (m *Memory) ListDelegations(_ context.Context, consumerRef string) ([]model.Delegation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []model.Delegation
	for _, d := range m.delegations {
		if d.Claims.ConsumerRef == consumerRef {
			d.SpentMinor = m.spent(d.Claims.DelegationID)
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Claims.IssuedAt > out[j].Claims.IssuedAt })
	return out, nil
}

func (m *Memory) RevokeDelegation(_ context.Context, id, consumerRef string, at time.Time) (model.Delegation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.delegations[id]
	if !ok || d.Claims.ConsumerRef != consumerRef {
		return d, ErrNotFound
	}
	if d.RevokedAt == nil {
		t := at.UTC()
		d.RevokedAt = &t
		m.delegations[id] = d
	}
	return d, nil
}

func (m *Memory) RecordIntent(_ context.Context, r *model.IntentRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := r.AgentID + "|" + r.Nonce
	if m.nonces[k] || m.intentIDs[r.IntentID] {
		return ErrReplay
	}
	m.nonces[k], m.intentIDs[r.IntentID] = true, true
	return nil
}

func (m *Memory) ReserveSpend(_ context.Context, delegationID, intentRecordID string, amount int64, limit *int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit != nil && m.spent(delegationID)+amount > *limit {
		return ErrLimitExceeded
	}
	m.reservations[intentRecordID] = reservation{delegationID, amount}
	return nil
}

func (m *Memory) ReleaseSpend(_ context.Context, intentRecordID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.reservations, intentRecordID)
	return nil
}

func (m *Memory) GetTelegraphByIdempotency(_ context.Context, key string) (*model.TelegraphRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.telegraph[key]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *t
	return &cp, nil
}

func (m *Memory) SaveTelegraph(_ context.Context, t *model.TelegraphRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ex, ok := m.telegraph[t.IdempotencyKey]; ok && ex.ID != t.ID {
		return ErrConflict
	}
	cp := *t
	m.telegraph[t.IdempotencyKey] = &cp
	return nil
}

func (m *Memory) TelegraphSpendSince(_ context.Context, since time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var s int64
	for _, t := range m.telegraph {
		if !t.Simulated && t.PriceMinor != nil && !t.CreatedAt.Before(since) {
			s += *t.PriceMinor
		}
	}
	return s, nil
}

func (m *Memory) SaveVerification(_ context.Context, v *model.Verification) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verifications[v.ID] = *v
	return nil
}

func (m *Memory) GetVerification(_ context.Context, id string) (model.Verification, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.verifications[id]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}

func (m *Memory) ListVerifications(_ context.Context, merchantID string, limit int) ([]model.Verification, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []model.Verification
	for _, v := range m.verifications {
		if merchantID == "" || v.MerchantID == merchantID {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) AppendAudit(_ context.Context, e model.AuditEvent) (model.AuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prev := evidence.GenesisHash
	if n := len(m.audit); n > 0 {
		prev = m.audit[n-1].EventHash
	}
	e = sealEvent(e, int64(len(m.audit)+1), prev)
	m.audit = append(m.audit, e)
	return e, nil
}

func (m *Memory) ListAudit(_ context.Context, merchantID string, limit int) ([]model.AuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []model.AuditEvent
	for i := len(m.audit) - 1; i >= 0 && (limit <= 0 || len(out) < limit); i-- {
		if merchantID == "" || m.audit[i].MerchantID == merchantID {
			out = append(out, m.audit[i])
		}
	}
	return out, nil
}

func (m *Memory) AllAudit(context.Context) ([]model.AuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.audit), nil
}

// TamperAuditForTest mutates an event in place (tests only).
func (m *Memory) TamperAuditForTest(i int, payloadHash string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audit[i].PayloadHash = payloadHash
}
