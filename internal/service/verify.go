// Package service orchestrates KYA: registration, delegation and the
// verification pipeline (local checks -> paid Telegraph intelligence -> policy).
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/superirale/kya-gateway/internal/delegation"
	"github.com/superirale/kya-gateway/internal/evidence"
	"github.com/superirale/kya-gateway/internal/identity"
	"github.com/superirale/kya-gateway/internal/model"
	"github.com/superirale/kya-gateway/internal/policy"
	"github.com/superirale/kya-gateway/internal/storage"
	"github.com/superirale/kya-gateway/internal/telegraph"
)

type Service struct {
	Store     storage.Store
	Issuer    *delegation.Issuer
	Intel     telegraph.IntelligenceClient
	Policy    policy.Config
	Mode      string // "local" | "competition"
	ClockSkew time.Duration
	Log       *slog.Logger
	Now       func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

type VerifyRequest struct {
	AgentID      string               `json:"agent_id"`
	MerchantID   string               `json:"merchant_id"`
	DelegationID string               `json:"delegation_id"`
	Intent       model.PurchaseIntent `json:"intent"`
	Signature    string               `json:"signature"`
}

var (
	idPattern       = regexp.MustCompile(`^[A-Za-z0-9_\-]{3,64}$`)
	noncePattern    = regexp.MustCompile(`^[A-Za-z0-9_\-]{16,128}$`)
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	currencyPattern = regexp.MustCompile(`^[A-Z]{3}$`)
	categoryPattern = regexp.MustCompile(`^[a-z0-9_\-]{1,32}$`)
)

// Validate enforces the strict purchase-intent schema (422 on failure).
func (r VerifyRequest) Validate() error {
	in := r.Intent
	switch {
	case !identity.ValidAgentID(r.AgentID):
		return invalid("agent_id invalid")
	case !idPattern.MatchString(r.MerchantID):
		return invalid("merchant_id invalid")
	case !idPattern.MatchString(r.DelegationID):
		return invalid("delegation_id invalid")
	case !idPattern.MatchString(in.IntentID):
		return invalid("intent.intent_id invalid")
	case in.Action == "":
		return invalid("intent.action required")
	case in.AmountMinor <= 0 || in.AmountMinor > 1<<53-1:
		return invalid("intent.amount_minor must be a positive integer in minor units")
	case !currencyPattern.MatchString(in.Currency):
		return invalid("intent.currency must be ISO 4217 uppercase")
	case !digestPattern.MatchString(in.CartDigest):
		return invalid("intent.cart_digest must be sha256:<64 lowercase hex>")
	case in.Category != "" && !categoryPattern.MatchString(in.Category):
		return invalid("intent.category invalid")
	case !noncePattern.MatchString(in.Nonce):
		return invalid("intent.nonce must be 16-128 base64url characters")
	case r.Signature == "":
		return invalid("signature required")
	}
	ts, err := time.Parse(time.RFC3339, in.Timestamp)
	if err != nil || ts.Format(time.RFC3339) != in.Timestamp || ts.Location() != time.UTC {
		return invalid("intent.timestamp must be canonical RFC 3339 UTC without fractional seconds, e.g. 2026-11-08T15:00:00Z")
	}
	return nil
}

// tracer records timeline steps.
type tracer struct {
	steps []model.TraceStep
	t0    time.Time
}

func (t *tracer) add(step string, st model.StepStatus, reason, detail string) {
	t.steps = append(t.steps, model.TraceStep{Step: step, Status: st, Reason: reason, Detail: detail, DurationMs: time.Since(t.t0).Milliseconds()})
	t.t0 = time.Now()
}

var pipeline = []string{"agent_signature", "nonce", "intent_timestamp", "delegation", "spend_reservation", "telegraph_purchase", "receipt_verification", "policy_decision"}

func (t *tracer) skipRemaining(reason string) {
	seen := map[string]bool{}
	for _, s := range t.steps {
		seen[s.Step] = true
	}
	for _, p := range pipeline {
		if !seen[p] && p != "policy_decision" {
			t.steps = append(t.steps, model.TraceStep{Step: p, Status: model.StepSkipped, Detail: reason})
		}
	}
}

// VerifyResult carries the verification plus the HTTP status to return.
type VerifyResult struct {
	Verification model.Verification
	HTTPStatus   int
}

// Verify runs the full decision pipeline for an authenticated merchant.
// simScenario is honoured only by the simulated intelligence adapter.
func (s *Service) Verify(ctx context.Context, callerMerchant string, r VerifyRequest, simScenario string) (VerifyResult, error) {
	if err := r.Validate(); err != nil {
		return VerifyResult{}, err
	}
	if r.MerchantID != callerMerchant {
		// Confused-deputy guard: a merchant may only verify intents addressed to itself.
		return VerifyResult{}, forbidden("merchant_id does not match the authenticated merchant")
	}
	now := s.now()
	tr := &tracer{t0: time.Now()}
	payload := model.SignedIntentPayload{AgentID: r.AgentID, MerchantID: r.MerchantID, DelegationID: r.DelegationID, Intent: r.Intent}
	msg, err := identity.IntentMessage(payload)
	if err != nil {
		return VerifyResult{}, invalid("intent cannot be canonicalized: " + err.Error())
	}
	v := model.Verification{
		ID: model.NewID("ver_"), EvidenceID: model.NewID("ev_"), IntentID: r.Intent.IntentID, AgentID: r.AgentID,
		MerchantID: r.MerchantID, DelegationID: r.DelegationID, AmountMinor: r.Intent.AmountMinor, Currency: r.Intent.Currency,
		IntentHash: identity.HashMessage(msg), PolicyVersion: s.Policy.Version, Mode: s.Mode, CreatedAt: now,
	}
	deny := func(status int, fails ...policy.HardFailure) (VerifyResult, error) {
		tr.skipRemaining("not reached: hard check failed; no intelligence purchased")
		out := policy.Evaluate(s.Policy, fails, nil)
		return s.finalize(ctx, &v, tr, out, status)
	}

	// 1. Agent identity + signature.
	agent, err := s.Store.GetAgent(ctx, r.AgentID)
	if errors.Is(err, storage.ErrNotFound) {
		tr.add("agent_signature", model.StepFail, policy.AgentNotRegistered, "no registered key for agent")
		return deny(200, policy.HardFailure{Reason: policy.AgentNotRegistered, Detail: "agent has no registered key"})
	} else if err != nil {
		return VerifyResult{}, err
	}
	sig, perr := identity.ParseSignature(r.Signature)
	if perr != nil || identity.Verify(agent.PublicKey, msg, sig) != nil {
		tr.add("agent_signature", model.StepFail, policy.InvalidAgentSig, "Ed25519 signature does not match canonical intent")
		return deny(200, policy.HardFailure{Reason: policy.InvalidAgentSig, Detail: "signature does not verify against registered key"})
	}
	if agent.Status != model.AgentActive {
		tr.add("agent_signature", model.StepFail, policy.AgentDisabled, "agent is disabled")
		return deny(200, policy.HardFailure{Reason: policy.AgentDisabled, Detail: "agent disabled"})
	}
	tr.add("agent_signature", model.StepPass, policy.AgentSignatureValid, fmt.Sprintf("key v%d fp %s", agent.KeyVersion, identity.Fingerprint(agent.PublicKey)))

	// 2. Atomic nonce + intent-id uniqueness (only after the signature is valid,
	// so third parties cannot burn an agent's nonces).
	rec := model.IntentRecord{ID: model.NewUUID(), IntentID: r.Intent.IntentID, AgentID: r.AgentID, DelegationID: r.DelegationID,
		MerchantID: r.MerchantID, AmountMinor: r.Intent.AmountMinor, Currency: r.Intent.Currency, CartDigest: r.Intent.CartDigest,
		Nonce: r.Intent.Nonce, IntentHash: v.IntentHash, ReceivedAt: now}
	if err := s.Store.RecordIntent(ctx, &rec); errors.Is(err, storage.ErrReplay) {
		tr.add("nonce", model.StepFail, policy.NonceReplay, "nonce or intent_id already used")
		return deny(409, policy.HardFailure{Reason: policy.NonceReplay, Detail: "replayed nonce or intent_id"})
	} else if err != nil {
		return VerifyResult{}, err
	}
	v.PurchaseIntentID = &rec.ID
	tr.add("nonce", model.StepPass, policy.NonceUnique, "")

	var fails []policy.HardFailure
	// 3. Timestamp window.
	ts, _ := time.Parse(time.RFC3339, r.Intent.Timestamp)
	if skew := now.Sub(ts); skew > s.ClockSkew || skew < -s.ClockSkew {
		fails = append(fails, policy.HardFailure{Reason: policy.TimestampOutOfWindow, Detail: fmt.Sprintf("skew %s exceeds %s", skew.Round(time.Second), s.ClockSkew)})
		tr.add("intent_timestamp", model.StepFail, policy.TimestampOutOfWindow, "")
	} else {
		tr.add("intent_timestamp", model.StepPass, "", fmt.Sprintf("skew %s", skew.Round(time.Second)))
	}

	// 4. Delegation: issuer signature, expiry, revocation, scope, amount.
	d, err := s.Store.GetDelegation(ctx, r.DelegationID)
	if errors.Is(err, storage.ErrNotFound) {
		fails = append(fails, policy.HardFailure{Reason: policy.DelegationNotFound, Detail: "unknown delegation"})
		tr.add("delegation", model.StepFail, policy.DelegationNotFound, "")
	} else if err != nil {
		return VerifyResult{}, err
	} else {
		dfails := s.Issuer.Check(d, payload, now)
		for _, f := range dfails {
			fails = append(fails, policy.HardFailure{Reason: f.Reason, Detail: f.Detail})
		}
		if len(dfails) > 0 {
			tr.add("delegation", model.StepFail, dfails[0].Reason, joinReasons(dfails))
		} else {
			tr.add("delegation", model.StepPass, policy.DelegationValid, fmt.Sprintf("limit %d %s, expires %s", d.Claims.MaxAmountMinor, d.Claims.Currency, d.Claims.ExpiresAt))
		}
	}
	if len(fails) > 0 {
		return deny(200, fails...)
	}

	// 5. Atomic cumulative spend reservation.
	if err := s.Store.ReserveSpend(ctx, d.Claims.DelegationID, rec.ID, r.Intent.AmountMinor, d.Claims.CumulativeLimitMinor); errors.Is(err, storage.ErrLimitExceeded) {
		tr.add("spend_reservation", model.StepFail, policy.CumulativeExceeded, "")
		return deny(200, policy.HardFailure{Reason: policy.CumulativeExceeded, Detail: "cumulative delegation budget exhausted"})
	} else if err != nil {
		return VerifyResult{}, err
	}
	tr.add("spend_reservation", model.StepPass, "", fmt.Sprintf("reserved %d", r.Intent.AmountMinor))

	// 6. Paid Telegraph intelligence.
	risk, tg := s.purchaseRisk(ctx, rec, payload, agent, d, simScenario, tr)
	v.Telegraph, v.TelegraphCalled = tg, true

	// 7-8. Policy.
	out := policy.Evaluate(s.Policy, nil, risk)
	if out.Decision == model.Deny {
		if err := s.Store.ReleaseSpend(ctx, rec.ID); err != nil {
			s.Log.Error("release spend failed", "err", err)
		}
	}
	return s.finalize(ctx, &v, tr, out, 200)
}

func joinReasons(fs []delegation.Failure) string {
	s := ""
	for i, f := range fs {
		if i > 0 {
			s += "; "
		}
		s += f.Reason + " (" + f.Detail + ")"
	}
	return s
}

func amountBucket(minor int64, cur string) string {
	major := minor / 100
	edges := []int64{50, 100, 250, 500, 1000, 5000}
	lo := int64(0)
	for _, e := range edges {
		if major < e {
			return fmt.Sprintf("%s_%d_%d", cur, lo, e)
		}
		lo = e
	}
	return fmt.Sprintf("%s_%d_plus", cur, lo)
}

func ageBucket(d time.Duration) string {
	switch {
	case d < time.Hour:
		return "lt_1h"
	case d < 24*time.Hour:
		return "lt_1d"
	case d < 7*24*time.Hour:
		return "lt_7d"
	case d < 30*24*time.Hour:
		return "lt_30d"
	}
	return "gte_30d"
}

func usageBucket(used, limit int64) string {
	if limit <= 0 {
		return "unknown"
	}
	pct := used * 100 / limit
	switch {
	case pct < 25:
		return "lt_25pct"
	case pct < 50:
		return "25_50pct"
	case pct < 75:
		return "50_75pct"
	}
	return "75_100pct"
}

func (s *Service) purchaseRisk(ctx context.Context, rec model.IntentRecord, p model.SignedIntentPayload, a model.Agent,
	d model.Delegation, simScenario string, tr *tracer) (*policy.Risk, *model.TelegraphRecord) {
	desc := s.Intel.Describe()
	mh := sha256.Sum256([]byte("merchant:" + p.MerchantID))
	limit := d.Claims.MaxAmountMinor
	used := p.Intent.AmountMinor
	if d.Claims.CumulativeLimitMinor != nil {
		limit, used = *d.Claims.CumulativeLimitMinor, d.SpentMinor+p.Intent.AmountMinor
	}
	iat, _ := time.Parse(time.RFC3339, d.Claims.IssuedAt)
	req := telegraph.RiskRequest{
		IdempotencyKey: "tg:" + rec.IntentHash, MerchantRef: "m_" + hex.EncodeToString(mh[:6]),
		AmountBucket: amountBucket(p.Intent.AmountMinor, p.Intent.Currency), Currency: p.Intent.Currency,
		Action: p.Intent.Action, Category: p.Intent.Category, AgentKeyAge: ageBucket(s.now().Sub(a.CreatedAt)),
		DelegationAge: ageBucket(s.now().Sub(iat)), DelegationUsage: usageBucket(used, limit),
	}
	if desc.Simulated {
		req.SimulateScenario = simScenario
	}
	tg := &model.TelegraphRecord{ID: model.NewUUID(), PurchaseIntentID: rec.ID, IdempotencyKey: req.IdempotencyKey,
		IntentName: desc.Intent, Network: desc.Network, Simulated: desc.Simulated, SettlementStatus: model.EvidenceRequested, CreatedAt: s.now()}
	// Persist REQUESTED first: the unique idempotency key prevents a duplicate paid call.
	if err := s.Store.SaveTelegraph(ctx, tg); err != nil {
		tr.add("telegraph_purchase", model.StepFail, policy.IntelUnavailable, "idempotency reservation failed")
		tr.add("receipt_verification", model.StepSkipped, "", "")
		return &policy.Risk{Intent: desc.Intent, Available: false, Detail: "duplicate or failed idempotency reservation"}, nil
	}
	// Detach from the caller's cancellation: once paying, finish and record.
	pctx := context.WithoutCancel(ctx)
	ev, err := s.Intel.PurchaseRisk(pctx, req)
	fillRecord(tg, ev)
	risk := &policy.Risk{Intent: ev.Intent, Simulated: ev.Simulated, Level: ev.RiskLevel, Score: ev.RiskScore}
	label := "Telegraph " + desc.Intent + " on " + desc.Network
	if desc.Simulated {
		label = "SIMULATED " + desc.Intent + " (no network purchase)"
	}
	if err != nil {
		code := telegraph.CodeOf(err)
		tg.ErrorCode = &code
		risk.Detail = code
		if code == telegraph.ErrCodeSpendCap || code == telegraph.ErrCodePriceCap {
			risk.Reason = policy.SpendCapReached
		}
		tr.add("telegraph_purchase", model.StepFail, policy.IntelUnavailable, label+": "+code)
		tr.add("receipt_verification", model.StepSkipped, "", "no delivered result to verify")
		tg.SettlementStatus = ev.State
		if tg.SettlementStatus == "" || tg.SettlementStatus == model.EvidenceRequested {
			tg.SettlementStatus = model.EvidenceFailed
		}
		_ = s.Store.SaveTelegraph(pctx, tg)
		s.Log.Warn("telegraph purchase failed", "code", code, "intent", desc.Intent, "latency_ms", ev.LatencyMs)
		return risk, tg
	}
	risk.Available = true
	price := "price n/a"
	if tg.PriceMinor != nil {
		price = fmt.Sprintf("price %d micro-%s", *tg.PriceMinor, deref(tg.PriceCurrency))
	}
	tr.add("telegraph_purchase", model.StepPass, "", fmt.Sprintf("%s; request %s; %s", label, tg.RequestID, price))

	vs, verr := s.Intel.VerifyEvidence(pctx, ev)
	if verr != nil {
		vs = telegraph.VerificationStatus{State: model.EvidenceUnverified, Note: verr.Error()}
	}
	tg.SettlementStatus, tg.VerificationNote = vs.State, vs.Note
	risk.State = vs.State
	switch {
	case vs.State == model.EvidenceSettled:
		tr.add("receipt_verification", model.StepPass, "", vs.Note)
	case desc.Simulated:
		tr.add("receipt_verification", model.StepWarn, policy.IntelSimulated, vs.Note)
	default:
		tr.add("receipt_verification", model.StepWarn, policy.SettlementUnverified, vs.Note)
	}
	if err := s.Store.SaveTelegraph(pctx, tg); err != nil {
		s.Log.Error("save telegraph record failed", "err", err)
	}
	return risk, tg
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func fillRecord(tg *model.TelegraphRecord, ev telegraph.RiskEvidence) {
	if ev.Intent != "" {
		tg.IntentName = ev.Intent
	}
	if ev.Network != "" {
		tg.Network = ev.Network
	}
	tg.Simulated = ev.Simulated
	tg.RequestID = ev.RequestID
	tg.ProviderID, tg.ProviderName = ev.ProviderID, ev.ProviderName
	tg.ReceiptID, tg.TxHash, tg.ExplorerURL = ev.ReceiptID, ev.TxHash, ev.ExplorerURL
	tg.PriceMinor, tg.PriceCurrency = ev.PriceMinor, ev.PriceCurrency
	tg.ResultHash, tg.Result, tg.Receipt = ev.ResultHash, ev.Result, ev.Receipt
	if ev.RiskLevel != "" {
		l := ev.RiskLevel
		tg.RiskLevel = &l
	}
	tg.RiskScore = ev.RiskScore
	if ev.LatencyMs > 0 || ev.State != "" {
		l := ev.LatencyMs
		tg.LatencyMs = &l
	}
	if ev.State != "" {
		tg.SettlementStatus = ev.State
	}
	tg.VerificationNote = ev.Note
}

func (s *Service) finalize(ctx context.Context, v *model.Verification, tr *tracer, out policy.Outcome, status int) (VerifyResult, error) {
	v.Decision, v.ReasonCodes, v.Explanation = out.Decision, out.Reasons, out.Explanation
	st := model.StepPass
	if out.Decision == model.Deny {
		st = model.StepFail
	} else if out.Decision == model.Review {
		st = model.StepWarn
	}
	tr.add("policy_decision", st, string(out.Decision), s.Policy.Version)
	v.Trace = tr.steps
	doc := buildDocument(*v)
	h, err := evidence.HashCanonical(doc)
	if err != nil {
		return VerifyResult{}, err
	}
	v.EvidenceHash = h
	if err := s.Store.SaveVerification(ctx, v); err != nil {
		return VerifyResult{}, err
	}
	s.audit(ctx, "verification", v.ID, "verification.decided", v.MerchantID, doc)
	attrs := []any{"verification_id", v.ID, "agent_id", v.AgentID, "merchant_id", v.MerchantID, "policy_version", v.PolicyVersion,
		"decision", v.Decision, "reason_codes", v.ReasonCodes, "telegraph_called", v.TelegraphCalled}
	if t := v.Telegraph; t != nil {
		attrs = append(attrs, "telegraph_request_id", t.RequestID, "settlement", t.SettlementStatus, "simulated", t.Simulated)
		if t.LatencyMs != nil {
			attrs = append(attrs, "telegraph_latency_ms", *t.LatencyMs)
		}
		if t.PriceMinor != nil {
			attrs = append(attrs, "telegraph_cost_minor", *t.PriceMinor)
		}
	}
	s.Log.Info("verification decided", attrs...)
	return VerifyResult{Verification: *v, HTTPStatus: status}, nil
}

// EvidenceDocument recomputes the hashed evidence bundle for a stored verification.
func (s *Service) EvidenceDocument(v model.Verification) (evidence.Document, bool) {
	doc := buildDocument(v)
	h, _ := evidence.HashCanonical(doc)
	return doc, h == v.EvidenceHash
}

func buildDocument(v model.Verification) evidence.Document {
	return evidence.Document{
		VerificationID: v.ID, EvidenceID: v.EvidenceID, IntentHash: v.IntentHash, AgentID: v.AgentID, MerchantID: v.MerchantID,
		DelegationID: v.DelegationID, AmountMinor: v.AmountMinor, Currency: v.Currency, PolicyVersion: v.PolicyVersion,
		Decision: string(v.Decision), ReasonCodes: v.ReasonCodes, Mode: v.Mode, Telegraph: evidence.DigestTelegraph(v.Telegraph),
		CreatedAt: v.CreatedAt.Format(time.RFC3339Nano),
	}
}
