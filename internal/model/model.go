// Package model holds the persistent domain records shared by KYA packages.
package model

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

type AgentStatus string

const (
	AgentActive   AgentStatus = "active"
	AgentDisabled AgentStatus = "disabled"
)

type Agent struct {
	ID             string      `json:"id"`
	AgentID        string      `json:"agent_id"`
	DeveloperLabel string      `json:"developer_label"`
	PublicKey      []byte      `json:"-"`
	KeyVersion     int         `json:"key_version"`
	Status         AgentStatus `json:"status"`
	CreatedAt      time.Time   `json:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at"`
}

type Challenge struct {
	ChallengeID string    `json:"challenge_id"`
	AgentID     string    `json:"agent_id"`
	Challenge   string    `json:"challenge"`
	Purpose     string    `json:"purpose"` // "register" | "rotate"
	ExpiresAt   time.Time `json:"expires_at"`
}

// DelegationClaims is exactly the object the issuer signs.
type DelegationClaims struct {
	DelegationID         string   `json:"delegation_id"`
	SubjectAgentID       string   `json:"subject_agent_id"`
	MerchantID           string   `json:"merchant_id"`
	Actions              []string `json:"actions"`
	MaxAmountMinor       int64    `json:"max_amount_minor"`
	CumulativeLimitMinor *int64   `json:"cumulative_limit_minor,omitempty"`
	Categories           []string `json:"categories,omitempty"`
	Currency             string   `json:"currency"`
	IssuedAt             string   `json:"issued_at"`
	ExpiresAt            string   `json:"expires_at"`
	Issuer               string   `json:"issuer"`
	Audience             string   `json:"audience"`
	ConsumerRef          string   `json:"consumer_ref"` // pseudonymous consumer reference, never PII
	IssuerKeyID          string   `json:"kid"`
}

type Delegation struct {
	ID            string           `json:"id"`
	Claims        DelegationClaims `json:"claims"`
	SignedPayload json.RawMessage  `json:"signed_payload"` // canonical claims JSON
	Signature     []byte           `json:"-"`
	SignatureB64  string           `json:"signature"`
	RevokedAt     *time.Time       `json:"revoked_at,omitempty"`
	SpentMinor    int64            `json:"spent_minor"`
}

// PurchaseIntent is the inner intent object a shopping agent signs.
type PurchaseIntent struct {
	IntentID    string `json:"intent_id"`
	Action      string `json:"action"`
	AmountMinor int64  `json:"amount_minor"`
	Currency    string `json:"currency"`
	CartDigest  string `json:"cart_digest"`
	Category    string `json:"category,omitempty"`
	Timestamp   string `json:"timestamp"`
	Nonce       string `json:"nonce"`
}

// SignedIntentPayload is the full object covered by the agent signature.
type SignedIntentPayload struct {
	AgentID      string         `json:"agent_id"`
	MerchantID   string         `json:"merchant_id"`
	DelegationID string         `json:"delegation_id"`
	Intent       PurchaseIntent `json:"intent"`
}

type IntentRecord struct {
	ID           string
	IntentID     string
	AgentID      string
	DelegationID string
	MerchantID   string
	AmountMinor  int64
	Currency     string
	CartDigest   string
	Nonce        string
	IntentHash   string
	ReceivedAt   time.Time
}

type EvidenceState string

const (
	EvidenceRequested  EvidenceState = "REQUESTED"
	EvidenceSettled    EvidenceState = "SETTLED"
	EvidenceFailed     EvidenceState = "FAILED"
	EvidenceUnverified EvidenceState = "UNVERIFIED"
)

// TelegraphRecord is the persisted view of one paid intelligence call.
// Optional fields stay nil unless actually observed from the network.
type TelegraphRecord struct {
	ID               string          `json:"id"`
	PurchaseIntentID string          `json:"purchase_intent_id"`
	IdempotencyKey   string          `json:"idempotency_key"`
	IntentName       string          `json:"intent_name"`
	Network          string          `json:"network"`
	Simulated        bool            `json:"simulated"`
	RequestID        string          `json:"request_id,omitempty"` // Telegraph signal_hash
	ProviderID       *string         `json:"provider_id,omitempty"`
	ProviderName     *string         `json:"provider_name,omitempty"`
	SettlementStatus EvidenceState   `json:"settlement_status"`
	ReceiptID        *string         `json:"receipt_id,omitempty"` // receipt_hash
	TxHash           *string         `json:"tx_hash,omitempty"`
	ExplorerURL      *string         `json:"explorer_url,omitempty"`
	PriceMinor       *int64          `json:"price_minor,omitempty"` // micro-USDC
	PriceCurrency    *string         `json:"price_currency,omitempty"`
	ResultHash       *string         `json:"result_hash,omitempty"`
	RiskLevel        *string         `json:"risk_level,omitempty"`
	RiskScore        *float64        `json:"risk_score,omitempty"`
	Result           json.RawMessage `json:"result,omitempty"`  // untrusted provider data, display only
	Receipt          json.RawMessage `json:"receipt,omitempty"` // decoded X-TELEGRAPH-RECEIPT
	VerificationNote string          `json:"verification_note,omitempty"`
	LatencyMs        *int            `json:"latency_ms,omitempty"`
	ErrorCode        *string         `json:"error_code,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
}

type Decision string

const (
	Allow  Decision = "ALLOW"
	Review Decision = "REVIEW"
	Deny   Decision = "DENY"
)

type StepStatus string

const (
	StepPass    StepStatus = "pass"
	StepFail    StepStatus = "fail"
	StepWarn    StepStatus = "warn"
	StepSkipped StepStatus = "skipped"
)

// TraceStep is one human-readable entry in the verification timeline.
type TraceStep struct {
	Step       string     `json:"step"`
	Status     StepStatus `json:"status"`
	Reason     string     `json:"reason,omitempty"`
	Detail     string     `json:"detail,omitempty"`
	DurationMs int64      `json:"duration_ms"`
}

type Verification struct {
	ID               string           `json:"verification_id"`
	PurchaseIntentID *string          `json:"purchase_intent_id,omitempty"`
	IntentID         string           `json:"intent_id"`
	AgentID          string           `json:"agent_id"`
	MerchantID       string           `json:"merchant_id"`
	DelegationID     string           `json:"delegation_id"`
	AmountMinor      int64            `json:"amount_minor"`
	Currency         string           `json:"currency"`
	IntentHash       string           `json:"intent_hash"`
	Decision         Decision         `json:"decision"`
	ReasonCodes      []string         `json:"reason_codes"`
	Explanation      []string         `json:"explanation"`
	PolicyVersion    string           `json:"policy_version"`
	Trace            []TraceStep      `json:"trace"`
	Telegraph        *TelegraphRecord `json:"telegraph,omitempty"`
	TelegraphCalled  bool             `json:"telegraph_called"`
	EvidenceID       string           `json:"evidence_id"`
	EvidenceHash     string           `json:"evidence_hash"`
	Mode             string           `json:"mode"`
	CreatedAt        time.Time        `json:"created_at"`
}

type AuditEvent struct {
	ID           string    `json:"id"`
	Seq          int64     `json:"seq"`
	EntityType   string    `json:"entity_type"`
	EntityID     string    `json:"entity_id"`
	EventType    string    `json:"event_type"`
	MerchantID   string    `json:"merchant_id,omitempty"`
	PayloadHash  string    `json:"payload_hash"`
	PreviousHash string    `json:"previous_hash"`
	EventHash    string    `json:"event_hash"`
	CreatedAt    time.Time `json:"created_at"`
}

type Stats struct {
	Total               int64            `json:"total"`
	ByDecision          map[string]int64 `json:"by_decision"`
	ByReason            map[string]int64 `json:"by_reason"`
	TelegraphCalls      int64            `json:"telegraph_calls"`
	TelegraphErrors     int64            `json:"telegraph_errors"`
	TelegraphSettled    int64            `json:"telegraph_settled"`
	TelegraphSpendMinor int64            `json:"telegraph_spend_minor"`
	RejectedBeforeSpend int64            `json:"rejected_before_spend"`
	AvgTelegraphLatency float64          `json:"avg_telegraph_latency_ms"`
}

// NewUUID returns a random RFC 4122 version 4 UUID.
func NewUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

// NewID returns prefix + 22 random base64url characters (128 bits).
func NewID(prefix string) string {
	return prefix + RandomToken(16)
}

func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
