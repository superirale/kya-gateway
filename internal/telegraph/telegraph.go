// Package telegraph is KYA's adapter boundary to Telegraph paid intelligence.
//
// The rest of KYA depends only on IntelligenceClient. Two implementations exist:
//   - X402Client: the real testnet flow (POST /engine/v1/ask, HTTP 402 challenge,
//     EIP-3009 payment authorization, X-TELEGRAPH-RECEIPT, signal verification).
//   - SimulatedClient: local-only deterministic results, always labeled
//     Simulated=true. Competition mode refuses to start with it.
//
// Provider output is untrusted data. Only enum levels and bounded numeric
// scores influence decisions; free text is stored for display only.
package telegraph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/superirale/kya-gateway/internal/model"
)

// RiskRequest contains only pseudonymous, bucketed transaction features.
// It must never carry customer PII, raw prompts or signing secrets.
type RiskRequest struct {
	IdempotencyKey   string
	MerchantRef      string // hash of merchant id
	AmountBucket     string // e.g. "USD_250_500"
	Currency         string
	Action           string
	Category         string
	AgentKeyAge      string // bucket, e.g. "lt_1d"
	DelegationAge    string
	DelegationUsage  string // bucket of share of limit used
	SimulateScenario string // honoured ONLY by SimulatedClient
}

// Subject renders the request as the free-text "subject" param expected by
// judgment intents such as FRAUD_RISK_GENERAL.
func (r RiskRequest) Subject() string {
	cat := r.Category
	if cat == "" {
		cat = "unspecified"
	}
	return fmt.Sprintf("Agent-initiated e-commerce payment awaiting merchant authorization. "+
		"merchant_ref=%s; action=%s; amount_bucket=%s; product_category=%s; "+
		"agent_key_age=%s; consumer_delegation_age=%s; delegation_limit_used=%s; "+
		"agent_identity=ed25519_proof_of_possession; consumer_delegation=signed_scoped_short_lived. "+
		"Assess the fraud risk of this payment.",
		r.MerchantRef, r.Action, r.AmountBucket, cat, r.AgentKeyAge, r.DelegationAge, r.DelegationUsage)
}

// RiskEvidence is everything observed for one purchase. Pointer fields stay
// nil unless the network actually returned them: never invent receipts.
type RiskEvidence struct {
	Intent        string
	Network       string
	Simulated     bool
	State         model.EvidenceState
	RequestID     string // signal_hash
	ProviderID    *string
	ProviderName  *string
	ReceiptID     *string // receipt_hash
	TxHash        *string
	ExplorerURL   *string
	PriceMinor    *int64 // micro-USDC
	PriceCurrency *string
	Payer         string
	PayTo         string
	Asset         string
	RiskLevel     string
	RiskScore     *float64
	Result        json.RawMessage
	ResultHash    *string
	Receipt       json.RawMessage
	LatencyMs     int
	ErrorCode     string
	Note          string
}

type VerificationStatus struct {
	State model.EvidenceState
	Note  string
}

type IntelligenceClient interface {
	PurchaseRisk(ctx context.Context, req RiskRequest) (RiskEvidence, error)
	VerifyEvidence(ctx context.Context, ev RiskEvidence) (VerificationStatus, error)
	// Describe returns non-secret configuration for status pages.
	Describe() Description
}

type Description struct {
	Adapter       string `json:"adapter"`
	Network       string `json:"network"`
	Intent        string `json:"intent"`
	Simulated     bool   `json:"simulated"`
	BaseURL       string `json:"base_url,omitempty"`
	PayerAddress  string `json:"payer_address,omitempty"`
	MaxPriceMinor int64  `json:"max_price_minor"`
	PriceCurrency string `json:"price_currency"`
}

// Error codes surfaced in evidence and decisions.
const (
	ErrCodeTimeout      = "TELEGRAPH_TIMEOUT"
	ErrCodeUnavailable  = "TELEGRAPH_UNAVAILABLE"
	ErrCodeNoMiner      = "TELEGRAPH_NO_COMPATIBLE_MINER"
	ErrCodePriceCap     = "TELEGRAPH_PRICE_ABOVE_CAP"
	ErrCodeSpendCap     = "TELEGRAPH_DAILY_SPEND_CAP"
	ErrCodeBadChallenge = "TELEGRAPH_BAD_PAYMENT_CHALLENGE"
	ErrCodePayment      = "TELEGRAPH_PAYMENT_REJECTED"
	ErrCodeSchema       = "TELEGRAPH_SCHEMA_MISMATCH"
	ErrCodeHTTP         = "TELEGRAPH_HTTP_ERROR"
)

// Error is a typed failure; Paid reports whether funds may have moved.
type Error struct {
	Code string
	Msg  string
	Paid bool
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func codeOf(err error) string {
	var te *Error
	if errors.As(err, &te) {
		return te.Code
	}
	return ErrCodeUnavailable
}

// CodeOf extracts a stable error code from any adapter error.
func CodeOf(err error) string { return codeOf(err) }

// Budget guards network spend (per-day cap). Reserve before paying; commit
// the actual amount or release on failure-before-payment.
type Budget interface {
	Reserve(amountMinor int64) (commit func(spent bool), err error)
}
