// Package api exposes the KYA REST API (see openapi/kya.yaml).
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/superirale/kya-gateway/internal/auth"
	"github.com/superirale/kya-gateway/internal/canonical"
	"github.com/superirale/kya-gateway/internal/delegation"
	"github.com/superirale/kya-gateway/internal/evidence"
	"github.com/superirale/kya-gateway/internal/identity"
	"github.com/superirale/kya-gateway/internal/model"
	"github.com/superirale/kya-gateway/internal/service"
	"github.com/superirale/kya-gateway/internal/storage"
	"github.com/superirale/kya-gateway/internal/telegraph"
)

type Server struct {
	Svc         *service.Service
	Merchants   *auth.MerchantKeys
	AdminKey    string
	Consumers   *auth.Consumers
	Sessions    *auth.Sessions
	CORSOrigins []string
	RatePerMin  int
	Budget      *telegraph.DailyBudget // nil for simulated
	Log         *slog.Logger

	rl rateLimiter
}

const maxBody = 64 << 10

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /v1/public/status", s.status)

	mux.HandleFunc("POST /v1/agents/challenge", s.challenge)
	mux.HandleFunc("POST /v1/agents/register", s.register)
	mux.HandleFunc("GET /v1/agents/{agent_id}", s.getAgent)
	mux.HandleFunc("POST /v1/agents/{agent_id}/rotate-key", s.rotateKey)
	mux.HandleFunc("POST /v1/agents/{agent_id}/disable", s.admin(s.setAgentStatus(model.AgentDisabled)))
	mux.HandleFunc("POST /v1/agents/{agent_id}/enable", s.admin(s.setAgentStatus(model.AgentActive)))

	mux.HandleFunc("POST /v1/consumers/login", s.login)
	mux.HandleFunc("POST /v1/delegations", s.consumer(s.createDelegation))
	mux.HandleFunc("GET /v1/delegations", s.consumer(s.listDelegations))
	mux.HandleFunc("POST /v1/delegations/{id}/revoke", s.consumer(s.revokeDelegation))

	mux.HandleFunc("POST /v1/verify-transactions", s.merchant(s.verify))
	mux.HandleFunc("GET /v1/verifications", s.merchant(s.listVerifications))
	mux.HandleFunc("GET /v1/verifications/{id}", s.merchant(s.getVerification))
	mux.HandleFunc("GET /v1/verifications/{id}/evidence", s.merchant(s.getEvidence))
	mux.HandleFunc("GET /v1/stats", s.merchant(s.stats))
	mux.HandleFunc("GET /v1/audit", s.merchant(s.listAudit))
	mux.HandleFunc("GET /v1/audit/verify", s.merchant(s.verifyAudit))

	return s.middleware(mux)
}

// ---------- middleware ----------

type ctxKey int

const (
	ctxMerchant ctxKey = iota
	ctxConsumer
)

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(c int) { w.status = c; w.ResponseWriter.WriteHeader(c) }

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		reqID := model.NewID("req_")
		h := w.Header()
		h.Set("X-Request-Id", reqID)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		h.Set("Referrer-Policy", "no-referrer")
		if origin := r.Header.Get("Origin"); origin != "" && slices.Contains(s.CORSOrigins, origin) {
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Vary", "Origin")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-KYA-Simulate")
			h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			h.Set("Access-Control-Max-Age", "600")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/healthz") && !s.rl.allow(clientKey(r), s.RatePerMin) {
			writeErr(w, &service.APIError{Status: 429, Code: "RATE_LIMITED", Msg: "too many requests"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		// Never log headers or bodies: they can contain API keys and signatures.
		s.Log.Info("http", "request_id", reqID, "method", r.Method, "path", r.URL.Path, "status", sw.status, "duration_ms", time.Since(start).Milliseconds())
	})
}

func bearer(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if t, ok := strings.CutPrefix(v, "Bearer "); ok {
		return strings.TrimSpace(t)
	}
	return ""
}

func clientKey(r *http.Request) string {
	if b := bearer(r); b != "" {
		return "k:" + evidence.HashBytes([]byte(b))[:24]
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return "ip:" + host
}

func (s *Server) merchant(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.Merchants.Lookup(bearer(r))
		if !ok {
			writeErr(w, service.Unauthorized("merchant API key required (Authorization: Bearer <key>)"))
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxMerchant, id)))
	}
}

func (s *Server) admin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.AdminKey == "" || !auth.EqualSecret(bearer(r), s.AdminKey) {
			writeErr(w, service.Unauthorized("admin key required"))
			return
		}
		h(w, r)
	}
}

func (s *Server) consumer(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := s.Sessions.Verify(bearer(r), time.Now())
		if err != nil {
			writeErr(w, service.Unauthorized("demo consumer session required"))
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxConsumer, s.Sessions.ConsumerRef(user))))
	}
}

func merchantOf(r *http.Request) string { return r.Context().Value(ctxMerchant).(string) }
func consumerOf(r *http.Request) string { return r.Context().Value(ctxConsumer).(string) }

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func (l *rateLimiter) allow(key string, perMin int) bool {
	if perMin <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buckets == nil {
		l.buckets = map[string]*bucket{}
	}
	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) > 50_000 { // crude memory bound
			l.buckets = map[string]*bucket{}
		}
		b = &bucket{tokens: float64(perMin), last: now}
		l.buckets[key] = b
	}
	b.tokens = min(float64(perMin), b.tokens+now.Sub(b.last).Minutes()*float64(perMin))
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	var ae *service.APIError
	if errors.As(err, &ae) {
		writeJSON(w, ae.Status, map[string]any{"error": ae})
		return
	}
	writeJSON(w, 500, map[string]any{"error": map[string]string{"code": "INTERNAL", "message": "internal error"}})
}

// decode reads a strict JSON body: no duplicate keys, no unknown fields.
func decode(r *http.Request, v any) error {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return service.BadRequest("body too large or unreadable")
	}
	if err := canonical.CheckNoDuplicateKeys(raw); err != nil {
		if errors.Is(err, canonical.ErrDuplicateKey) {
			return service.BadRequest("duplicate JSON keys are not allowed")
		}
		return service.BadRequest("malformed JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var ute *json.UnmarshalTypeError
		if errors.As(err, &ute) || strings.Contains(err.Error(), "unknown field") {
			return service.Invalid(err.Error())
		}
		return service.BadRequest("malformed JSON")
	}
	if dec.More() {
		return service.BadRequest("trailing data after JSON body")
	}
	return nil
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	var ae *service.APIError
	if !errors.As(err, &ae) {
		s.Log.Error("internal error", "err", err)
	}
	writeErr(w, err)
}

// ---------- handlers ----------

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Svc.Store.Ping(ctx); err != nil {
		writeJSON(w, 503, map[string]string{"status": "unavailable", "component": "database"})
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ready"})
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	d := s.Svc.Intel.Describe()
	out := map[string]any{
		"mode": s.Svc.Mode, "policy_version": s.Svc.Policy.Version, "telegraph": d,
		"fail_closed_decision": s.Svc.Policy.FailClosedDecision, "accept_simulated": s.Svc.Policy.AcceptSimulated,
		"issuer": map[string]string{"kid": s.Svc.Issuer.KeyID, "public_key": identity.EncodeB64URL(s.Svc.Issuer.PublicKey())},
		"labels": map[string]string{
			"merchant_payment": "SIMULATED: no real merchandise payment is taken",
			"consumers":        "SYNTHETIC demo accounts; not identity proofing",
		},
	}
	if s.Budget != nil {
		spent, cap := s.Budget.Snapshot()
		out["spend"] = map[string]any{"spent_today_minor": spent, "daily_cap_minor": cap, "currency": "USDC", "unit": "micro"}
	}
	writeJSON(w, 200, out)
}

func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentID string `json:"agent_id"`
		Purpose string `json:"purpose,omitempty"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, err)
		return
	}
	ch, err := s.Svc.IssueChallenge(r.Context(), req.AgentID, req.Purpose)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"challenge_id": ch.ChallengeID, "challenge": ch.Challenge, "purpose": ch.Purpose,
		"expires_at": ch.ExpiresAt.Format(time.RFC3339), "signing_domain": canonical.DomainAgentChallenge})
}

func agentView(a model.Agent) map[string]any {
	return map[string]any{"agent_id": a.AgentID, "developer_label": a.DeveloperLabel, "status": a.Status, "key_version": a.KeyVersion,
		"public_key": identity.EncodeB64URL(a.PublicKey), "key_fingerprint": identity.Fingerprint(a.PublicKey), "created_at": a.CreatedAt,
		"identity_note": "Key possession verified. Real-world operator identity NOT verified."}
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var req service.RegisterRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, err)
		return
	}
	a, err := s.Svc.RegisterAgent(r.Context(), req)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, agentView(a))
}

func (s *Server) getAgent(w http.ResponseWriter, r *http.Request) {
	a, err := s.Svc.GetAgent(r.Context(), r.PathValue("agent_id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, agentView(a))
}

func (s *Server) rotateKey(w http.ResponseWriter, r *http.Request) {
	var req service.RotateRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, err)
		return
	}
	a, err := s.Svc.RotateAgentKey(r.Context(), r.PathValue("agent_id"), req)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, agentView(a))
}

func (s *Server) setAgentStatus(st model.AgentStatus) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := s.Svc.SetAgentStatus(r.Context(), r.PathValue("agent_id"), st)
		if err != nil {
			s.fail(w, err)
			return
		}
		writeJSON(w, 200, agentView(a))
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, err)
		return
	}
	if !s.Consumers.Check(req.Username, req.Password) {
		writeErr(w, service.Unauthorized("invalid demo credentials"))
		return
	}
	tok, exp := s.Sessions.Issue(req.Username, time.Now())
	writeJSON(w, 200, map[string]any{"token": tok, "expires_at": exp, "consumer_ref": s.Sessions.ConsumerRef(req.Username),
		"note": "Demo consumer account. Not production identity proofing."})
}

func delegationView(d model.Delegation) map[string]any {
	return map[string]any{"delegation_id": d.Claims.DelegationID, "claims": d.Claims, "signed_payload": d.SignedPayload,
		"signature": d.SignatureB64, "revoked_at": d.RevokedAt, "spent_minor": d.SpentMinor, "signing_domain": canonical.DomainDelegation}
}

func (s *Server) createDelegation(w http.ResponseWriter, r *http.Request) {
	var req delegation.Request
	if err := decode(r, &req); err != nil {
		s.fail(w, err)
		return
	}
	d, err := s.Svc.CreateDelegation(r.Context(), consumerOf(r), req)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, delegationView(d))
}

func (s *Server) listDelegations(w http.ResponseWriter, r *http.Request) {
	ds, err := s.Svc.ListDelegations(r.Context(), consumerOf(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]map[string]any, 0, len(ds))
	for _, d := range ds {
		out = append(out, delegationView(d))
	}
	writeJSON(w, 200, map[string]any{"delegations": out})
}

func (s *Server) revokeDelegation(w http.ResponseWriter, r *http.Request) {
	d, err := s.Svc.RevokeDelegation(r.Context(), consumerOf(r), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, delegationView(d))
}

// VerifyResponse is the merchant-facing decision.
func verifyResponse(v model.Verification) map[string]any {
	out := map[string]any{
		"verification_id": v.ID, "decision": v.Decision, "reason_codes": v.ReasonCodes, "explanation": v.Explanation,
		"policy_version": v.PolicyVersion, "evidence_id": v.EvidenceID, "evidence_hash": v.EvidenceHash,
		"intent_hash": v.IntentHash, "telegraph_called": v.TelegraphCalled, "trace": v.Trace, "mode": v.Mode,
		"created_at": v.CreatedAt, "telegraph": nil,
	}
	if t := v.Telegraph; t != nil {
		var cost any
		if t.PriceMinor != nil && !t.Simulated {
			cost = map[string]any{"amount_minor": *t.PriceMinor, "currency": deref(t.PriceCurrency), "decimals": 6}
		}
		out["telegraph"] = map[string]any{
			"network": t.Network, "intent": t.IntentName, "simulated": t.Simulated, "settlement_status": t.SettlementStatus,
			"request_id": nilIfEmpty(t.RequestID), "receipt_id": t.ReceiptID, "tx_hash": t.TxHash, "explorer_url": t.ExplorerURL,
			"provider_id": t.ProviderID, "observed_cost": cost, "latency_ms": t.LatencyMs, "error_code": t.ErrorCode,
			"risk_level": t.RiskLevel, "risk_score": t.RiskScore, "verification_note": t.VerificationNote,
		}
	}
	return out
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	var req service.VerifyRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, err)
		return
	}
	sim := ""
	if s.Svc.Mode == "local" {
		sim = r.Header.Get("X-KYA-Simulate")
	}
	res, err := s.Svc.Verify(r.Context(), merchantOf(r), req, sim)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, res.HTTPStatus, verifyResponse(res.Verification))
}

func (s *Server) ownedVerification(w http.ResponseWriter, r *http.Request) (model.Verification, bool) {
	v, err := s.Svc.Store.GetVerification(r.Context(), r.PathValue("id"))
	if errors.Is(err, storage.ErrNotFound) || (err == nil && v.MerchantID != merchantOf(r)) {
		writeErr(w, service.NotFound("verification not found"))
		return v, false
	} else if err != nil {
		s.fail(w, err)
		return v, false
	}
	return v, true
}

func (s *Server) getVerification(w http.ResponseWriter, r *http.Request) {
	if v, ok := s.ownedVerification(w, r); ok {
		writeJSON(w, 200, verifyResponse(v))
	}
}

func (s *Server) getEvidence(w http.ResponseWriter, r *http.Request) {
	v, ok := s.ownedVerification(w, r)
	if !ok {
		return
	}
	doc, intact := s.Svc.EvidenceDocument(v)
	out := map[string]any{"evidence_id": v.EvidenceID, "evidence_hash": v.EvidenceHash, "hash_matches": intact, "document": doc,
		"trace": v.Trace, "explanation": v.Explanation,
		"labels": map[string]string{"merchant_checkout": "SIMULATED", "provider_result": "untrusted third-party data, display only"}}
	if t := v.Telegraph; t != nil {
		out["telegraph_record"] = t
	}
	writeJSON(w, 200, out)
}

func limitParam(r *http.Request, def int) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n <= 0 || n > 500 {
		return def
	}
	return n
}

func (s *Server) listVerifications(w http.ResponseWriter, r *http.Request) {
	vs, err := s.Svc.Store.ListVerifications(r.Context(), merchantOf(r), limitParam(r, 50))
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]map[string]any, 0, len(vs))
	for _, v := range vs {
		m := verifyResponse(v)
		delete(m, "trace")
		m["agent_id"], m["amount_minor"], m["currency"], m["intent_id"] = v.AgentID, v.AmountMinor, v.Currency, v.IntentID
		out = append(out, m)
	}
	writeJSON(w, 200, map[string]any{"verifications": out})
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	vs, err := s.Svc.Store.ListVerifications(r.Context(), merchantOf(r), 5000)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, storage.ComputeStats(vs))
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	es, err := s.Svc.Store.ListAudit(r.Context(), merchantOf(r), limitParam(r, 100))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"events": es})
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	es, err := s.Svc.Store.AllAudit(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	broken := evidence.VerifyChain(es)
	out := map[string]any{"events": len(es), "intact": broken < 0,
		"note": "Hash chain is tamper-evident, not a guarantee of immutability."}
	if broken >= 0 {
		out["first_broken_seq"] = es[broken].Seq
	} else if len(es) > 0 {
		out["head_hash"] = es[len(es)-1].EventHash
	}
	writeJSON(w, 200, out)
}
