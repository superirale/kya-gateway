package delegation

import (
	"testing"
	"time"

	"github.com/superirale/kya-gateway/internal/model"
)

var now = time.Date(2026, 11, 8, 15, 0, 0, 0, time.UTC)

func base() Request {
	return Request{AgentID: "agent_demo_001", MerchantID: "merchant_demo_001", Actions: []string{"purchase"},
		MaxAmountMinor: 50000, Currency: "USD", ExpiresInSeconds: 1800}
}

func TestValidate(t *testing.T) {
	i64 := func(v int64) *int64 { return &v }
	bad := map[string]func(*Request){
		"agent":            func(r *Request) { r.AgentID = "A" },
		"merchant":         func(r *Request) { r.MerchantID = "M!" },
		"no actions":       func(r *Request) { r.Actions = nil },
		"unknown action":   func(r *Request) { r.Actions = []string{"refund"} },
		"zero amount":      func(r *Request) { r.MaxAmountMinor = 0 },
		"cumulative < max": func(r *Request) { r.CumulativeLimitMinor = i64(100) },
		"category":         func(r *Request) { r.Categories = []string{"Bad Cat"} },
		"currency":         func(r *Request) { r.Currency = "usd" },
		"both expiries":    func(r *Request) { r.ExpiresAt = "2026-11-08T16:00:00Z" },
		"no expiry":        func(r *Request) { r.ExpiresInSeconds = 0 },
		"past expiry":      func(r *Request) { r.ExpiresInSeconds = 0; r.ExpiresAt = "2026-11-08T14:00:00Z" },
		"bad expiry":       func(r *Request) { r.ExpiresInSeconds = 0; r.ExpiresAt = "tomorrow" },
		"too long":         func(r *Request) { r.ExpiresInSeconds = 3 * 86400 },
	}
	for name, mut := range bad {
		r := base()
		mut(&r)
		if _, err := r.Validate(now); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	r := base()
	r.ExpiresInSeconds, r.ExpiresAt = 0, "2026-11-08T15:30:00Z"
	if exp, err := r.Validate(now); err != nil || !exp.Equal(now.Add(30*time.Minute)) {
		t.Fatalf("valid absolute expiry: %v %v", exp, err)
	}
}

func issuer(t *testing.T) *Issuer {
	i, err := NewIssuer("k1", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func payload(d model.Delegation) model.SignedIntentPayload {
	return model.SignedIntentPayload{AgentID: d.Claims.SubjectAgentID, MerchantID: d.Claims.MerchantID, DelegationID: d.Claims.DelegationID,
		Intent: model.PurchaseIntent{Action: "purchase", AmountMinor: 35000, Currency: "USD", Category: "electronics"}}
}

func reasons(fs []Failure) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.Reason] = true
	}
	return m
}

func TestCheck(t *testing.T) {
	iss := issuer(t)
	r := base()
	r.Categories = []string{"electronics"}
	d, err := iss.Issue(r, "cr_1", now)
	if err != nil {
		t.Fatal(err)
	}
	if fs := iss.Check(d, payload(d), now); len(fs) != 0 {
		t.Fatalf("valid delegation failed: %v", fs)
	}
	p := payload(d)
	p.AgentID, p.MerchantID = "agent_other", "merchant_other"
	p.Intent.Action, p.Intent.Currency, p.Intent.Category, p.Intent.AmountMinor = "refund", "EUR", "toys", 60000
	got := reasons(iss.Check(d, p, now))
	for _, want := range []string{ReasonAgentMismatch, ReasonMerchant, ReasonAction, ReasonCurrency, ReasonCategory, ReasonAmount} {
		if !got[want] {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if !reasons(iss.Check(d, payload(d), now.Add(time.Hour)))[ReasonExpired] {
		t.Error("expiry not enforced")
	}
	if !reasons(iss.Check(d, payload(d), now.Add(-time.Hour)))[ReasonNotYetValid] {
		t.Error("future issued_at not rejected")
	}
	rev := d
	tm := now
	rev.RevokedAt = &tm
	if !reasons(iss.Check(rev, payload(d), now))[ReasonRevoked] {
		t.Error("revocation not enforced")
	}
}

func TestSignatureBindsClaims(t *testing.T) {
	iss := issuer(t)
	d, _ := iss.Issue(base(), "cr_1", now)
	tampered := d
	tampered.Claims.MaxAmountMinor = 1_000_000 // DB row edited after signing
	if fs := iss.Check(tampered, payload(d), now); len(fs) != 1 || fs[0].Reason != ReasonSignatureInvalid {
		t.Fatalf("tampered claims accepted: %v", fs)
	}
	other, _ := NewIssuer("k1", append(make([]byte, 31), 1))
	if fs := other.Check(d, payload(d), now); len(fs) != 1 || fs[0].Reason != ReasonSignatureInvalid {
		t.Fatalf("foreign issuer accepted: %v", fs)
	}
	unknownKid := d
	unknownKid.Claims.IssuerKeyID = "k9"
	if iss.VerifySignature(unknownKid) == nil {
		t.Fatal("unknown kid accepted")
	}
	if _, err := NewIssuer("k", []byte("short")); err == nil {
		t.Fatal("short seed accepted")
	}
}
