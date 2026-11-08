// Package policy is KYA's deterministic, versioned decision engine.
//
// Evaluate is a pure function: identical inputs and Config always produce the
// identical decision, reason codes (in a stable order) and explanation.
package policy

import (
	"fmt"
	"math"
	"slices"

	"github.com/superirale/kya-gateway/internal/model"
)

// Stable reason codes. Never rename; add new ones instead.
const (
	AgentSignatureValid  = "AGENT_SIGNATURE_VALID"
	DelegationValid      = "DELEGATION_VALID"
	NonceUnique          = "NONCE_UNIQUE"
	RiskAcceptable       = "RISK_ACCEPTABLE"
	InvalidAgentSig      = "INVALID_AGENT_SIGNATURE"
	AgentNotRegistered   = "AGENT_NOT_REGISTERED"
	AgentDisabled        = "AGENT_DISABLED"
	DelegationNotFound   = "DELEGATION_NOT_FOUND"
	NonceReplay          = "NONCE_REPLAY"
	TimestampOutOfWindow = "INTENT_TIMESTAMP_OUT_OF_WINDOW"
	CumulativeExceeded   = "CUMULATIVE_LIMIT_EXCEEDED"
	SettlementUnverified = "TELEGRAPH_SETTLEMENT_UNVERIFIED"
	IntelUnavailable     = "RISK_INTELLIGENCE_UNAVAILABLE"
	IntelSimulated       = "RISK_INTELLIGENCE_SIMULATED"
	RiskAboveThreshold   = "RISK_ABOVE_THRESHOLD"
	RiskElevated         = "RISK_ELEVATED_REVIEW"
	RiskUnrecognized     = "RISK_RESULT_UNRECOGNIZED"
	SpendCapReached      = "TELEGRAPH_SPEND_CAP_REACHED"
)

// IntentThresholds calibrates one Telegraph intent's output to decisions.
// There is no universal risk scale: each intent must be configured.
type IntentThresholds struct {
	// LevelDecision maps the intent's categorical output (e.g. risk_level).
	LevelDecision map[string]model.Decision `json:"level_decision"`
	// ReviewScore / DenyScore apply to a numeric score where higher = riskier.
	ReviewScore *float64 `json:"review_score,omitempty"`
	DenyScore   *float64 `json:"deny_score,omitempty"`
	ScoreMin    float64  `json:"score_min"`
	ScoreMax    float64  `json:"score_max"`
}

type Config struct {
	Version string `json:"version"`
	// FailClosedDecision applies when intelligence is unavailable/unverified.
	// REVIEW (default) or DENY ("strict merchant policy"). Never ALLOW.
	FailClosedDecision model.Decision `json:"fail_closed_decision"`
	// RequireSettled requires evidence state SETTLED before ALLOW.
	RequireSettled bool `json:"require_settled"`
	// AcceptSimulated allows local simulated intelligence to ALLOW. It is
	// forced false in competition mode.
	AcceptSimulated bool                        `json:"accept_simulated"`
	Intents         map[string]IntentThresholds `json:"intents"`
}

func f(v float64) *float64 { return &v }

// DefaultConfig is "hackathon-v1".
func DefaultConfig() Config {
	fraudRisk := IntentThresholds{
		LevelDecision: map[string]model.Decision{
			"LOW": model.Allow, "MEDIUM": model.Allow, "HIGH": model.Review, "CRITICAL": model.Deny,
		},
		ReviewScore: f(0.60), DenyScore: f(0.85), ScoreMin: 0, ScoreMax: 1,
	}
	fraudDetection := IntentThresholds{
		LevelDecision: map[string]model.Decision{
			"LEGITIMATE": model.Allow, "LOW": model.Allow,
			"INCONCLUSIVE": model.Review, "SUSPICIOUS": model.Review, "ELEVATED": model.Review,
			"LIKELY_FRAUD": model.Deny, "FRAUD": model.Deny, "HIGH": model.Deny,
		},
		ReviewScore: f(0.60), DenyScore: f(0.85), ScoreMin: 0, ScoreMax: 1,
	}
	return Config{
		Version:            "hackathon-v1",
		FailClosedDecision: model.Review,
		RequireSettled:     true,
		AcceptSimulated:    false,
		Intents: map[string]IntentThresholds{
			"FRAUD_RISK_GENERAL":      fraudRisk,
			"FRAUD_DETECTION_GENERAL": fraudDetection,
		},
	}
}

// HardFailure is a local, pre-intelligence check failure.
type HardFailure struct {
	Reason string
	Detail string
}

// Risk is the policy-relevant projection of Telegraph evidence.
type Risk struct {
	Intent    string
	Available bool
	State     model.EvidenceState
	Simulated bool
	Level     string   // categorical output, "" if absent
	Score     *float64 // numeric output, nil if absent
	Detail    string   // why unavailable
	Reason    string   // override reason when unavailable (e.g. spend cap)
}

type Outcome struct {
	Decision    model.Decision
	Reasons     []string
	Explanation []string
}

func severity(d model.Decision) int {
	switch d {
	case model.Deny:
		return 2
	case model.Review:
		return 1
	}
	return 0
}

func worst(a, b model.Decision) model.Decision {
	if severity(b) > severity(a) {
		return b
	}
	return a
}

// Evaluate produces the decision. hard must contain every local failure;
// when non-empty, risk is ignored and the result is DENY.
func Evaluate(cfg Config, hard []HardFailure, risk *Risk) Outcome {
	if len(hard) > 0 {
		o := Outcome{Decision: model.Deny}
		for _, h := range hard {
			if !slices.Contains(o.Reasons, h.Reason) {
				o.Reasons = append(o.Reasons, h.Reason)
			}
			o.Explanation = append(o.Explanation, fmt.Sprintf("%s: %s", h.Reason, h.Detail))
		}
		o.Explanation = append(o.Explanation, "Denied before any paid intelligence request.")
		return o
	}
	failClosed := cfg.FailClosedDecision
	if failClosed != model.Deny {
		failClosed = model.Review // never allow fail-open configuration
	}
	base := []string{AgentSignatureValid, DelegationValid, NonceUnique}
	closed := func(reason, why string) Outcome {
		return Outcome{Decision: failClosed, Reasons: append(base, reason),
			Explanation: []string{"Local authorization checks passed.", why, fmt.Sprintf("Fail-closed policy returns %s.", failClosed)}}
	}
	if risk == nil || !risk.Available {
		reason, why := IntelUnavailable, "Risk intelligence unavailable."
		if risk != nil {
			if risk.Reason != "" {
				reason = risk.Reason
			}
			if risk.Detail != "" {
				why = "Risk intelligence unavailable: " + risk.Detail
			}
		}
		return closed(reason, why)
	}
	if risk.Simulated && !cfg.AcceptSimulated {
		return closed(IntelSimulated, "Risk result is SIMULATED and this policy only accepts real Telegraph evidence.")
	}
	if cfg.RequireSettled && !risk.Simulated && risk.State != model.EvidenceSettled {
		return closed(SettlementUnverified, fmt.Sprintf("Telegraph evidence state is %s, not independently verified as SETTLED.", risk.State))
	}
	th, ok := cfg.Intents[risk.Intent]
	if !ok {
		return closed(RiskUnrecognized, fmt.Sprintf("No calibrated thresholds for intent %q.", risk.Intent))
	}

	decision, recognized := model.Allow, false
	var expl []string
	if risk.Level != "" {
		if d, ok := th.LevelDecision[risk.Level]; ok {
			recognized = true
			decision = worst(decision, d)
			expl = append(expl, fmt.Sprintf("Telegraph %s level %s maps to %s.", risk.Intent, risk.Level, d))
		} else {
			expl = append(expl, fmt.Sprintf("Unknown level %q ignored.", risk.Level))
		}
	}
	if s := risk.Score; s != nil && !math.IsNaN(*s) && !math.IsInf(*s, 0) && *s >= th.ScoreMin && *s <= th.ScoreMax {
		recognized = true
		sd := model.Allow
		if th.DenyScore != nil && *s >= *th.DenyScore {
			sd = model.Deny
		} else if th.ReviewScore != nil && *s >= *th.ReviewScore {
			sd = model.Review
		}
		decision = worst(decision, sd)
		expl = append(expl, fmt.Sprintf("Risk score %.3f maps to %s (review >= %s, deny >= %s).", *s, sd, fmtp(th.ReviewScore), fmtp(th.DenyScore)))
	} else if risk.Score != nil {
		expl = append(expl, "Out-of-range risk score ignored.")
	}
	if !recognized {
		return closed(RiskUnrecognized, "Provider result had no recognized risk level or valid score.")
	}
	o := Outcome{Decision: decision, Explanation: append([]string{"Local authorization checks passed."}, expl...)}
	switch decision {
	case model.Allow:
		o.Reasons = append(base, RiskAcceptable)
	case model.Review:
		o.Reasons = append(base, RiskElevated)
	case model.Deny:
		o.Reasons = append(base, RiskAboveThreshold)
	}
	if risk.Simulated {
		o.Explanation = append(o.Explanation, "NOTE: risk result was SIMULATED locally; no Telegraph purchase occurred.")
	}
	return o
}

func fmtp(p *float64) string {
	if p == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.2f", *p)
}
