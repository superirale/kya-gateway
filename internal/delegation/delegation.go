// Package delegation issues and validates consumer-signed spending delegations.
//
// For the hackathon, the issuer is KYA's demo consumer-auth service: an
// authenticated demo consumer asks KYA to sign a delegation with the issuer
// key. This is NOT production identity proofing; see docs/threat-model.md.
package delegation

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/superirale/kya-gateway/internal/canonical"
	"github.com/superirale/kya-gateway/internal/identity"
	"github.com/superirale/kya-gateway/internal/model"
)

const (
	DefaultIssuer   = "kya-demo-consumer-auth"
	DefaultAudience = "kya-gateway"
	MaxLifetime     = 24 * time.Hour
)

var (
	AllowedActions  = []string{"purchase"}
	currencyPattern = regexp.MustCompile(`^[A-Z]{3}$`)
	merchantPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_\-]{2,63}$`)
	categoryPattern = regexp.MustCompile(`^[a-z0-9_\-]{1,32}$`)
)

// Issuer signs delegation claims. Multiple verification keys may be trusted
// (keyed by kid) to allow issuer-key rotation.
type Issuer struct {
	KeyID    string
	priv     ed25519.PrivateKey
	trusted  map[string]ed25519.PublicKey
	Name     string
	Audience string
}

func NewIssuer(kid string, seed []byte) (*Issuer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("delegation: issuer seed must be %d bytes", ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Issuer{
		KeyID: kid, priv: priv, Name: DefaultIssuer, Audience: DefaultAudience,
		trusted: map[string]ed25519.PublicKey{kid: priv.Public().(ed25519.PublicKey)},
	}, nil
}

func (i *Issuer) PublicKey() ed25519.PublicKey { return i.trusted[i.KeyID] }

// Request is a consumer's request to delegate authority.
type Request struct {
	AgentID              string   `json:"agent_id"`
	MerchantID           string   `json:"merchant_id"`
	Actions              []string `json:"actions"`
	MaxAmountMinor       int64    `json:"max_amount_minor"`
	CumulativeLimitMinor *int64   `json:"cumulative_limit_minor,omitempty"`
	Categories           []string `json:"categories,omitempty"`
	Currency             string   `json:"currency"`
	ExpiresAt            string   `json:"expires_at,omitempty"`
	ExpiresInSeconds     int64    `json:"expires_in_seconds,omitempty"`
}

func (r Request) Validate(now time.Time) (time.Time, error) {
	if !identity.ValidAgentID(r.AgentID) {
		return time.Time{}, errors.New("agent_id invalid")
	}
	if !merchantPattern.MatchString(r.MerchantID) {
		return time.Time{}, errors.New("merchant_id invalid")
	}
	if len(r.Actions) == 0 {
		return time.Time{}, errors.New("actions required")
	}
	for _, a := range r.Actions {
		if !slices.Contains(AllowedActions, a) {
			return time.Time{}, fmt.Errorf("action %q not supported", a)
		}
	}
	if r.MaxAmountMinor <= 0 || r.MaxAmountMinor > canonical.MaxSafeInteger {
		return time.Time{}, errors.New("max_amount_minor must be a positive integer")
	}
	if r.CumulativeLimitMinor != nil && (*r.CumulativeLimitMinor < r.MaxAmountMinor || *r.CumulativeLimitMinor > canonical.MaxSafeInteger) {
		return time.Time{}, errors.New("cumulative_limit_minor must be >= max_amount_minor")
	}
	for _, c := range r.Categories {
		if !categoryPattern.MatchString(c) {
			return time.Time{}, fmt.Errorf("category %q invalid", c)
		}
	}
	if !currencyPattern.MatchString(r.Currency) {
		return time.Time{}, errors.New("currency must be ISO 4217 uppercase")
	}
	var exp time.Time
	switch {
	case r.ExpiresAt != "" && r.ExpiresInSeconds != 0:
		return time.Time{}, errors.New("set only one of expires_at, expires_in_seconds")
	case r.ExpiresAt != "":
		t, err := time.Parse(time.RFC3339, r.ExpiresAt)
		if err != nil {
			return time.Time{}, errors.New("expires_at must be RFC 3339")
		}
		exp = t.UTC()
	case r.ExpiresInSeconds > 0:
		exp = now.Add(time.Duration(r.ExpiresInSeconds) * time.Second)
	default:
		return time.Time{}, errors.New("expiry required")
	}
	if !exp.After(now) {
		return time.Time{}, errors.New("expiry must be in the future")
	}
	if exp.Sub(now) > MaxLifetime {
		return time.Time{}, errors.New("delegations are short-lived: maximum 24h")
	}
	return exp.Truncate(time.Second), nil
}

// Issue builds and signs claims for an authenticated consumer.
func (i *Issuer) Issue(r Request, consumerRef string, now time.Time) (model.Delegation, error) {
	exp, err := r.Validate(now)
	if err != nil {
		return model.Delegation{}, err
	}
	claims := model.DelegationClaims{
		DelegationID:         model.NewID("dlg_"),
		SubjectAgentID:       r.AgentID,
		MerchantID:           r.MerchantID,
		Actions:              slices.Clone(r.Actions),
		MaxAmountMinor:       r.MaxAmountMinor,
		CumulativeLimitMinor: r.CumulativeLimitMinor,
		Categories:           slices.Clone(r.Categories),
		Currency:             r.Currency,
		IssuedAt:             now.UTC().Truncate(time.Second).Format(time.RFC3339),
		ExpiresAt:            exp.Format(time.RFC3339),
		Issuer:               i.Name,
		Audience:             i.Audience,
		ConsumerRef:          consumerRef,
		IssuerKeyID:          i.KeyID,
	}
	payload, err := canonical.Marshal(claims)
	if err != nil {
		return model.Delegation{}, err
	}
	msg, _ := canonical.SigningMessage(canonical.DomainDelegation, claims)
	sig := ed25519.Sign(i.priv, msg)
	return model.Delegation{
		ID: model.NewUUID(), Claims: claims, SignedPayload: payload,
		Signature: sig, SignatureB64: identity.EncodeB64URL(sig),
	}, nil
}

// Failure reason codes (stable API).
const (
	ReasonSignatureInvalid = "DELEGATION_SIGNATURE_INVALID"
	ReasonExpired          = "DELEGATION_EXPIRED"
	ReasonNotYetValid      = "DELEGATION_NOT_YET_VALID"
	ReasonRevoked          = "DELEGATION_REVOKED"
	ReasonAgentMismatch    = "DELEGATION_AGENT_MISMATCH"
	ReasonMerchant         = "MERCHANT_NOT_ALLOWED"
	ReasonAction           = "ACTION_NOT_ALLOWED"
	ReasonCategory         = "CATEGORY_NOT_ALLOWED"
	ReasonAmount           = "AMOUNT_EXCEEDS_DELEGATION"
	ReasonCurrency         = "CURRENCY_MISMATCH"
	ReasonAudience         = "DELEGATION_AUDIENCE_INVALID"
)

type Failure struct {
	Reason string
	Detail string
}

// VerifySignature checks the issuer signature over the stored canonical claims
// and that the stored claims struct matches what was signed.
func (i *Issuer) VerifySignature(d model.Delegation) error {
	pub, ok := i.trusted[d.Claims.IssuerKeyID]
	if !ok {
		return errors.New("unknown issuer key id")
	}
	recomputed, err := canonical.Marshal(d.Claims)
	if err != nil {
		return err
	}
	if string(recomputed) != string(d.SignedPayload) {
		return errors.New("stored claims do not match signed payload")
	}
	msg, _ := canonical.SigningMessage(canonical.DomainDelegation, d.Claims)
	return identity.Verify(pub, msg, d.Signature)
}

// Check validates the delegation against a signed purchase intent. It returns
// every failed rule (not just the first) so the decision trace is complete.
func (i *Issuer) Check(d model.Delegation, p model.SignedIntentPayload, now time.Time) []Failure {
	var out []Failure
	c := d.Claims
	if err := i.VerifySignature(d); err != nil {
		return []Failure{{ReasonSignatureInvalid, err.Error()}}
	}
	if c.Issuer != i.Name || c.Audience != i.Audience {
		out = append(out, Failure{ReasonAudience, "issuer/audience not trusted by this gateway"})
	}
	if d.RevokedAt != nil {
		out = append(out, Failure{ReasonRevoked, "revoked at " + d.RevokedAt.UTC().Format(time.RFC3339)})
	}
	exp, err1 := time.Parse(time.RFC3339, c.ExpiresAt)
	iat, err2 := time.Parse(time.RFC3339, c.IssuedAt)
	if err1 != nil || err2 != nil || !now.Before(exp) {
		out = append(out, Failure{ReasonExpired, "expired at " + c.ExpiresAt})
	} else if now.Add(time.Minute).Before(iat) {
		out = append(out, Failure{ReasonNotYetValid, "issued in the future"})
	}
	if c.SubjectAgentID != p.AgentID {
		out = append(out, Failure{ReasonAgentMismatch, "delegation subject is a different agent"})
	}
	if c.MerchantID != p.MerchantID {
		out = append(out, Failure{ReasonMerchant, fmt.Sprintf("delegation scoped to %s", c.MerchantID)})
	}
	if !slices.Contains(c.Actions, p.Intent.Action) {
		out = append(out, Failure{ReasonAction, fmt.Sprintf("action %q not delegated", p.Intent.Action)})
	}
	if len(c.Categories) > 0 && !slices.Contains(c.Categories, p.Intent.Category) {
		out = append(out, Failure{ReasonCategory, fmt.Sprintf("category %q not delegated", p.Intent.Category)})
	}
	if c.Currency != p.Intent.Currency {
		out = append(out, Failure{ReasonCurrency, fmt.Sprintf("delegation currency %s", c.Currency)})
	}
	if p.Intent.AmountMinor > c.MaxAmountMinor {
		out = append(out, Failure{ReasonAmount, fmt.Sprintf("%d exceeds limit %d", p.Intent.AmountMinor, c.MaxAmountMinor)})
	}
	return out
}
