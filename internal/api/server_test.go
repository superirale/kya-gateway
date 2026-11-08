package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/superirale/kya-gateway/internal/auth"
	"github.com/superirale/kya-gateway/internal/delegation"
	"github.com/superirale/kya-gateway/internal/identity"
	"github.com/superirale/kya-gateway/internal/model"
	"github.com/superirale/kya-gateway/internal/policy"
	"github.com/superirale/kya-gateway/internal/service"
	"github.com/superirale/kya-gateway/internal/storage"
	"github.com/superirale/kya-gateway/internal/telegraph"
)

const merchantKey = "test-merchant-key-000000001"

func newServer(t *testing.T) *httptest.Server {
	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	iss, _ := delegation.NewIssuer("k1", seed)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pol := policy.DefaultConfig()
	pol.AcceptSimulated = true
	svc := &service.Service{Store: storage.NewMemory(), Issuer: iss, Intel: &telegraph.SimulatedClient{}, Policy: pol,
		Mode: "local", ClockSkew: 5 * time.Minute, Log: log}
	mk, _ := auth.ParseMerchantKeys("merchant_demo_001:" + merchantKey + ",merchant_two:other-merchant-key-00002")
	s := &Server{Svc: svc, Merchants: mk, AdminKey: "admin-key-for-tests", Consumers: auth.ParseConsumers("alice:pw"),
		Sessions: auth.NewSessions([]byte("0123456789abcdef0123456789abcdef"), time.Hour), CORSOrigins: []string{"http://ok.test"}, Log: log}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func call(t *testing.T, srv *httptest.Server, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rdr = strings.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		rdr = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, srv.URL+path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestEndToEndHTTP(t *testing.T) {
	srv := newServer(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubB64 := identity.EncodeB64URL(pub)

	st, ch := call(t, srv, "POST", "/v1/agents/challenge", "", map[string]string{"agent_id": "agent_demo_001"})
	if st != 201 {
		t.Fatalf("challenge %d %v", st, ch)
	}
	exp, _ := time.Parse(time.RFC3339, ch["expires_at"].(string))
	msg, _ := identity.ChallengeMessage(model.Challenge{ChallengeID: ch["challenge_id"].(string), AgentID: "agent_demo_001",
		Challenge: ch["challenge"].(string), ExpiresAt: exp}, pubB64)
	st, _ = call(t, srv, "POST", "/v1/agents/register", "", map[string]string{"agent_id": "agent_demo_001", "developer_label": "t",
		"public_key": pubB64, "challenge_id": ch["challenge_id"].(string), "signed_challenge": identity.EncodeB64URL(ed25519.Sign(priv, msg))})
	if st != 201 {
		t.Fatalf("register %d", st)
	}

	if st, _ := call(t, srv, "POST", "/v1/consumers/login", "", map[string]string{"username": "alice", "password": "nope"}); st != 401 {
		t.Fatalf("bad login %d", st)
	}
	_, login := call(t, srv, "POST", "/v1/consumers/login", "", map[string]string{"username": "alice", "password": "pw"})
	tok := login["token"].(string)
	if st, _ := call(t, srv, "POST", "/v1/delegations", "", map[string]any{}); st != 401 {
		t.Fatalf("unauth delegation %d", st)
	}
	st, dlg := call(t, srv, "POST", "/v1/delegations", tok, map[string]any{"agent_id": "agent_demo_001", "merchant_id": "merchant_demo_001",
		"actions": []string{"purchase"}, "max_amount_minor": 50000, "currency": "USD", "expires_in_seconds": 1800})
	if st != 201 {
		t.Fatalf("delegation %d %v", st, dlg)
	}
	dlgID := dlg["delegation_id"].(string)

	mkReq := func(amount int64) map[string]any {
		in := model.PurchaseIntent{IntentID: model.NewID("pi_"), Action: "purchase", AmountMinor: amount, Currency: "USD",
			CartDigest: "sha256:" + strings.Repeat("ab", 32), Timestamp: time.Now().UTC().Format(time.RFC3339), Nonce: model.RandomToken(16)}
		m, _ := identity.IntentMessage(model.SignedIntentPayload{AgentID: "agent_demo_001", MerchantID: "merchant_demo_001", DelegationID: dlgID, Intent: in})
		return map[string]any{"agent_id": "agent_demo_001", "merchant_id": "merchant_demo_001", "delegation_id": dlgID, "intent": in,
			"signature": identity.EncodeB64URL(ed25519.Sign(priv, m))}
	}

	req := mkReq(35000)
	if st, _ := call(t, srv, "POST", "/v1/verify-transactions", "", req); st != 401 {
		t.Fatalf("no merchant key %d", st)
	}
	if st, _ := call(t, srv, "POST", "/v1/verify-transactions", "other-merchant-key-00002", req); st != 403 {
		t.Fatalf("confused deputy %d", st)
	}
	st, v := call(t, srv, "POST", "/v1/verify-transactions", merchantKey, req)
	if st != 200 || v["decision"] != "ALLOW" {
		t.Fatalf("verify %d %v", st, v)
	}
	tg := v["telegraph"].(map[string]any)
	if tg["simulated"] != true || tg["receipt_id"] != nil || tg["observed_cost"] != nil {
		t.Fatalf("simulated evidence must be labeled and receipt-free: %v", tg)
	}
	if st, v2 := call(t, srv, "POST", "/v1/verify-transactions", merchantKey, req); st != 409 || v2["decision"] != "DENY" {
		t.Fatalf("replay %d %v", st, v2)
	}
	if st, v3 := call(t, srv, "POST", "/v1/verify-transactions", merchantKey, mkReq(65000)); st != 200 || v3["decision"] != "DENY" || v3["telegraph_called"] != false {
		t.Fatalf("over limit %d %v", st, v3)
	}

	id := v["verification_id"].(string)
	if st, ev := call(t, srv, "GET", "/v1/verifications/"+id+"/evidence", merchantKey, nil); st != 200 || ev["hash_matches"] != true {
		t.Fatalf("evidence %d %v", st, ev)
	}
	if st, _ := call(t, srv, "GET", "/v1/verifications/"+id, "other-merchant-key-00002", nil); st != 404 {
		t.Fatalf("cross-merchant read %d", st)
	}
	if st, a := call(t, srv, "GET", "/v1/audit/verify", merchantKey, nil); st != 200 || a["intact"] != true {
		t.Fatalf("audit %d %v", st, a)
	}

	// Revoke -> denied before any purchase.
	if st, _ := call(t, srv, "POST", "/v1/delegations/"+dlgID+"/revoke", tok, nil); st != 200 {
		t.Fatalf("revoke %d", st)
	}
	if _, v4 := call(t, srv, "POST", "/v1/verify-transactions", merchantKey, mkReq(1000)); v4["decision"] != "DENY" {
		t.Fatalf("revoked %v", v4)
	}
}

func TestStrictDecoding(t *testing.T) {
	srv := newServer(t)
	if st, _ := call(t, srv, "POST", "/v1/agents/challenge", "", `{"agent_id":"agent_a","agent_id":"agent_b"}`); st != 400 {
		t.Fatalf("duplicate keys %d", st)
	}
	if st, _ := call(t, srv, "POST", "/v1/agents/challenge", "", `{"agent_id":"agent_a","extra":1}`); st != 422 {
		t.Fatalf("unknown field %d", st)
	}
	if st, _ := call(t, srv, "POST", "/v1/agents/challenge", "", `{"agent_id":`); st != 400 {
		t.Fatalf("malformed %d", st)
	}
	if st, _ := call(t, srv, "POST", "/v1/verify-transactions", merchantKey, `{"agent_id":"agent_demo_001","intent":{"amount_minor":1.5}}`); st != 422 {
		t.Fatalf("float amount %d", st)
	}
}

func TestCORSAllowlist(t *testing.T) {
	srv := newServer(t)
	for origin, want := range map[string]string{"http://ok.test": "http://ok.test", "http://evil.test": ""} {
		req, _ := http.NewRequest("OPTIONS", srv.URL+"/v1/verify-transactions", nil)
		req.Header.Set("Origin", origin)
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != want {
			t.Errorf("origin %s: got %q", origin, got)
		}
	}
}
