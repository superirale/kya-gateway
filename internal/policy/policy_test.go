package policy

import (
	"math"
	"reflect"
	"testing"

	"github.com/superirale/kya-gateway/internal/model"
)

func fp(v float64) *float64 { return &v }

func TestEvaluateTable(t *testing.T) {
	cfg := DefaultConfig()
	settled := func(level string, score *float64) *Risk {
		return &Risk{Intent: "FRAUD_RISK_GENERAL", Available: true, State: model.EvidenceSettled, Level: level, Score: score}
	}
	cases := []struct {
		name   string
		hard   []HardFailure
		risk   *Risk
		want   model.Decision
		reason string
	}{
		{"hard failure wins", []HardFailure{{"AMOUNT_EXCEEDS_DELEGATION", "x"}}, settled("LOW", fp(0)), model.Deny, "AMOUNT_EXCEEDS_DELEGATION"},
		{"low allow", nil, settled("LOW", fp(0.1)), model.Allow, RiskAcceptable},
		{"medium allow", nil, settled("MEDIUM", fp(0.3)), model.Allow, RiskAcceptable},
		{"high review", nil, settled("HIGH", nil), model.Review, RiskElevated},
		{"critical deny", nil, settled("CRITICAL", nil), model.Deny, RiskAboveThreshold},
		{"low level but high score", nil, settled("LOW", fp(0.9)), model.Deny, RiskAboveThreshold},
		{"score only review", nil, settled("", fp(0.65)), model.Review, RiskElevated},
		{"nan score unrecognized", nil, settled("", fp(math.NaN())), model.Review, RiskUnrecognized},
		{"out of range score", nil, settled("", fp(7)), model.Review, RiskUnrecognized},
		{"unknown level", nil, settled("BANANA", nil), model.Review, RiskUnrecognized},
		{"unavailable", nil, &Risk{Intent: "FRAUD_RISK_GENERAL"}, model.Review, IntelUnavailable},
		{"nil risk", nil, nil, model.Review, IntelUnavailable},
		{"unverified", nil, &Risk{Intent: "FRAUD_RISK_GENERAL", Available: true, State: model.EvidenceUnverified, Level: "LOW"}, model.Review, SettlementUnverified},
		{"simulated rejected", nil, &Risk{Intent: "FRAUD_RISK_GENERAL", Available: true, Simulated: true, Level: "LOW"}, model.Review, IntelSimulated},
		{"uncalibrated intent", nil, &Risk{Intent: "WEATHER_FORECAST_GENERAL", Available: true, State: model.EvidenceSettled, Level: "LOW"}, model.Review, RiskUnrecognized},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := Evaluate(cfg, c.hard, c.risk)
			if o.Decision != c.want {
				t.Fatalf("got %s want %s (%v)", o.Decision, c.want, o.Reasons)
			}
			found := false
			for _, r := range o.Reasons {
				found = found || r == c.reason
			}
			if !found {
				t.Fatalf("reasons %v missing %s", o.Reasons, c.reason)
			}
		})
	}
}

func TestFailOpenConfigImpossible(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FailClosedDecision = model.Allow
	if o := Evaluate(cfg, nil, nil); o.Decision != model.Review {
		t.Fatalf("misconfigured fail-open produced %s", o.Decision)
	}
}

func TestDeterministic(t *testing.T) {
	cfg := DefaultConfig()
	r := &Risk{Intent: "FRAUD_RISK_GENERAL", Available: true, State: model.EvidenceSettled, Level: "HIGH", Score: fp(0.7)}
	a, b := Evaluate(cfg, nil, r), Evaluate(cfg, nil, r)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("non-deterministic")
	}
	h := []HardFailure{{"B", "1"}, {"A", "2"}, {"B", "3"}}
	if o := Evaluate(cfg, h, nil); !reflect.DeepEqual(o.Reasons, []string{"B", "A"}) {
		t.Fatalf("unstable/duplicated reasons %v", o.Reasons)
	}
}

func TestSettledButEmptyResultFailsClosed(t *testing.T) {
	r := &Risk{Intent: "FRAUD_RISK_GENERAL", Available: true, State: model.EvidenceSettled}
	if o := Evaluate(DefaultConfig(), nil, r); o.Decision != model.Review || o.Reasons[len(o.Reasons)-1] != RiskUnrecognized {
		t.Fatalf("empty paid result must fail closed: %v %v", o.Decision, o.Reasons)
	}
}
