// Package evidence builds evidence documents and the tamper-evident audit
// hash chain. The chain makes after-the-fact edits detectable; it does not
// make records immutable (a DB superuser can rewrite the whole chain).
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/superirale/kya-gateway/internal/canonical"
	"github.com/superirale/kya-gateway/internal/model"
)

var GenesisHash = "sha256:" + strings.Repeat("0", 64)

func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// HashCanonical hashes the canonical JSON of v.
func HashCanonical(v any) (string, error) {
	b, err := canonical.Marshal(v)
	if err != nil {
		return "", err
	}
	return HashBytes(b), nil
}

type chainedFields struct {
	ID           string `json:"id"`
	Seq          int64  `json:"seq"`
	EntityType   string `json:"entity_type"`
	EntityID     string `json:"entity_id"`
	EventType    string `json:"event_type"`
	MerchantID   string `json:"merchant_id"`
	PayloadHash  string `json:"payload_hash"`
	PreviousHash string `json:"previous_hash"`
	CreatedAt    string `json:"created_at"`
}

// EventHash computes the chained hash of an event (all fields but EventHash).
func EventHash(e model.AuditEvent) string {
	h, _ := HashCanonical(chainedFields{
		ID: e.ID, Seq: e.Seq, EntityType: e.EntityType, EntityID: e.EntityID, EventType: e.EventType,
		MerchantID: e.MerchantID, PayloadHash: e.PayloadHash, PreviousHash: e.PreviousHash,
		CreatedAt: e.CreatedAt.UTC().Format(time.RFC3339Nano),
	})
	return h
}

// VerifyChain checks ordering, linkage and every event hash. It returns the
// index of the first broken event, or -1 if the chain is intact.
func VerifyChain(events []model.AuditEvent) int {
	prev := GenesisHash
	for i, e := range events {
		if e.Seq != int64(i+1) || e.PreviousHash != prev || EventHash(e) != e.EventHash {
			return i
		}
		prev = e.EventHash
	}
	return -1
}

// Document is the hashed evidence bundle for one verification. Scores are
// rendered as strings so the document stays integer-only canonical JSON.
type Document struct {
	VerificationID string           `json:"verification_id"`
	EvidenceID     string           `json:"evidence_id"`
	IntentHash     string           `json:"intent_hash"`
	AgentID        string           `json:"agent_id"`
	MerchantID     string           `json:"merchant_id"`
	DelegationID   string           `json:"delegation_id"`
	AmountMinor    int64            `json:"amount_minor"`
	Currency       string           `json:"currency"`
	PolicyVersion  string           `json:"policy_version"`
	Decision       string           `json:"decision"`
	ReasonCodes    []string         `json:"reason_codes"`
	Mode           string           `json:"mode"`
	Telegraph      *TelegraphDigest `json:"telegraph,omitempty"`
	CreatedAt      string           `json:"created_at"`
}

type TelegraphDigest struct {
	Intent           string `json:"intent"`
	Network          string `json:"network"`
	Simulated        bool   `json:"simulated"`
	RequestID        string `json:"request_id"`
	SettlementStatus string `json:"settlement_status"`
	ReceiptID        string `json:"receipt_id"`
	TxHash           string `json:"tx_hash"`
	PriceMinor       int64  `json:"price_minor"`
	ResultHash       string `json:"result_hash"`
	RiskLevel        string `json:"risk_level"`
	RiskScore        string `json:"risk_score"`
	ErrorCode        string `json:"error_code"`
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

func DigestTelegraph(t *model.TelegraphRecord) *TelegraphDigest {
	if t == nil {
		return nil
	}
	score := ""
	if t.RiskScore != nil {
		score = strings.TrimRight(strings.TrimRight(formatFloat(*t.RiskScore), "0"), ".")
	}
	return &TelegraphDigest{
		Intent: t.IntentName, Network: t.Network, Simulated: t.Simulated, RequestID: t.RequestID,
		SettlementStatus: string(t.SettlementStatus), ReceiptID: deref(t.ReceiptID), TxHash: deref(t.TxHash),
		PriceMinor: deref(t.PriceMinor), ResultHash: deref(t.ResultHash), RiskLevel: deref(t.RiskLevel),
		RiskScore: score, ErrorCode: deref(t.ErrorCode),
	}
}

func formatFloat(f float64) string { return strconv.FormatFloat(f, 'f', 6, 64) }
