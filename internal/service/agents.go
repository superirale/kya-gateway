package service

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"github.com/superirale/kya-gateway/internal/evidence"
	"github.com/superirale/kya-gateway/internal/identity"
	"github.com/superirale/kya-gateway/internal/model"
	"github.com/superirale/kya-gateway/internal/storage"
)

const challengeTTL = 5 * time.Minute

func (s *Service) IssueChallenge(ctx context.Context, agentID, purpose string) (model.Challenge, error) {
	if !identity.ValidAgentID(agentID) {
		return model.Challenge{}, invalid("agent_id must match ^[a-z0-9][a-z0-9_-]{2,63}$")
	}
	if purpose == "" {
		purpose = "register"
	}
	if purpose != "register" && purpose != "rotate" {
		return model.Challenge{}, invalid("purpose must be register or rotate")
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	c := model.Challenge{
		ChallengeID: model.NewID("ch_"), AgentID: agentID, Challenge: identity.EncodeB64URL(b),
		Purpose: purpose, ExpiresAt: s.now().Add(challengeTTL).UTC().Truncate(time.Second),
	}
	return c, s.Store.CreateChallenge(ctx, c)
}

func (s *Service) consumeChallenge(ctx context.Context, id, agentID, purpose string) (model.Challenge, error) {
	ch, err := s.Store.ConsumeChallenge(ctx, id, s.now())
	if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrExpired) {
		return ch, unauthorized("challenge unknown, used or expired")
	}
	if err != nil {
		return ch, err
	}
	if ch.AgentID != agentID || ch.Purpose != purpose {
		return ch, unauthorized("challenge was issued for a different agent or purpose")
	}
	return ch, nil
}

type RegisterRequest struct {
	AgentID         string `json:"agent_id"`
	DeveloperLabel  string `json:"developer_label"`
	PublicKey       string `json:"public_key"`
	ChallengeID     string `json:"challenge_id"`
	SignedChallenge string `json:"signed_challenge"`
}

func (s *Service) RegisterAgent(ctx context.Context, r RegisterRequest) (model.Agent, error) {
	if !identity.ValidAgentID(r.AgentID) {
		return model.Agent{}, invalid("agent_id invalid")
	}
	if len(r.DeveloperLabel) > 80 {
		return model.Agent{}, invalid("developer_label too long")
	}
	pub, err := identity.ParsePublicKey(r.PublicKey)
	if err != nil {
		return model.Agent{}, invalid(err.Error())
	}
	sig, err := identity.ParseSignature(r.SignedChallenge)
	if err != nil {
		return model.Agent{}, invalid(err.Error())
	}
	ch, err := s.consumeChallenge(ctx, r.ChallengeID, r.AgentID, "register")
	if err != nil {
		return model.Agent{}, err
	}
	msg, _ := identity.ChallengeMessage(ch, identity.EncodeB64URL(pub))
	if identity.Verify(pub, msg, sig) != nil {
		return model.Agent{}, unauthorized("challenge signature invalid: proof of possession failed")
	}
	now := s.now().UTC()
	a := model.Agent{ID: model.NewUUID(), AgentID: r.AgentID, DeveloperLabel: r.DeveloperLabel, PublicKey: pub,
		KeyVersion: 1, Status: model.AgentActive, CreatedAt: now, UpdatedAt: now}
	if err := s.Store.CreateAgent(ctx, &a); errors.Is(err, storage.ErrConflict) {
		return model.Agent{}, conflict("AGENT_EXISTS", "agent already registered; use key rotation")
	} else if err != nil {
		return model.Agent{}, err
	}
	s.audit(ctx, "agent", a.ID, "agent.registered", "", map[string]any{"agent_id": a.AgentID, "key_fp": identity.Fingerprint(pub), "key_version": 1})
	return a, nil
}

type RotateRequest struct {
	NewPublicKey    string `json:"new_public_key"`
	ChallengeID     string `json:"challenge_id"`
	OldKeySignature string `json:"old_key_signature"`
	NewKeySignature string `json:"new_key_signature"`
}

func (s *Service) RotateAgentKey(ctx context.Context, agentID string, r RotateRequest) (model.Agent, error) {
	newPub, err := identity.ParsePublicKey(r.NewPublicKey)
	if err != nil {
		return model.Agent{}, invalid(err.Error())
	}
	oldSig, err1 := identity.ParseSignature(r.OldKeySignature)
	newSig, err2 := identity.ParseSignature(r.NewKeySignature)
	if err1 != nil || err2 != nil {
		return model.Agent{}, invalid("signatures must be 64-byte base64url")
	}
	ch, err := s.consumeChallenge(ctx, r.ChallengeID, agentID, "rotate")
	if err != nil {
		return model.Agent{}, err
	}
	a, err := s.Store.GetAgent(ctx, agentID)
	if err != nil {
		return model.Agent{}, notFound("agent not found")
	}
	if a.Status != model.AgentActive {
		return model.Agent{}, forbidden("disabled agents cannot rotate keys")
	}
	msg, _ := identity.RotateMessage(ch, a.KeyVersion, identity.EncodeB64URL(newPub))
	if identity.Verify(a.PublicKey, msg, oldSig) != nil || identity.Verify(newPub, msg, newSig) != nil {
		return model.Agent{}, unauthorized("rotation requires valid signatures from both the current and new key")
	}
	updated, err := s.Store.RotateAgentKey(ctx, agentID, a.KeyVersion, newPub)
	if errors.Is(err, storage.ErrConflict) {
		return model.Agent{}, conflict("KEY_VERSION_CONFLICT", "key rotated concurrently; retry")
	} else if err != nil {
		return model.Agent{}, err
	}
	s.audit(ctx, "agent", a.ID, "agent.key_rotated", "", map[string]any{"agent_id": agentID, "key_fp": identity.Fingerprint(newPub), "key_version": updated.KeyVersion})
	return updated, nil
}

func (s *Service) SetAgentStatus(ctx context.Context, agentID string, st model.AgentStatus) (model.Agent, error) {
	a, err := s.Store.SetAgentStatus(ctx, agentID, st)
	if errors.Is(err, storage.ErrNotFound) {
		return a, notFound("agent not found")
	}
	if err == nil {
		s.audit(ctx, "agent", a.ID, "agent."+string(st), "", map[string]any{"agent_id": agentID})
	}
	return a, err
}

func (s *Service) GetAgent(ctx context.Context, agentID string) (model.Agent, error) {
	a, err := s.Store.GetAgent(ctx, agentID)
	if errors.Is(err, storage.ErrNotFound) {
		return a, notFound("agent not found")
	}
	return a, err
}

func (s *Service) audit(ctx context.Context, entityType, entityID, eventType, merchantID string, payload any) {
	h, err := evidence.HashCanonical(payload)
	if err != nil {
		s.Log.Error("audit hash failed", "err", err)
		return
	}
	if _, err := s.Store.AppendAudit(ctx, model.AuditEvent{EntityType: entityType, EntityID: entityID, EventType: eventType,
		MerchantID: merchantID, PayloadHash: h, CreatedAt: s.now()}); err != nil {
		s.Log.Error("audit append failed", "err", err, "event", eventType)
	}
}
