package storage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/superirale/kya-gateway/internal/evidence"
	"github.com/superirale/kya-gateway/internal/model"
)

// Conformance tests run against Memory always, and against Postgres when
// KYA_TEST_DATABASE_URL is set (use a throwaway database: tables are truncated).
func stores(t *testing.T) map[string]Store {
	out := map[string]Store{"memory": NewMemory()}
	if url := os.Getenv("KYA_TEST_DATABASE_URL"); url != "" {
		ctx := context.Background()
		pg, err := OpenPostgres(ctx, url)
		if err != nil {
			t.Fatalf("postgres: %v", err)
		}
		// Disable the append-only trigger only for truncation in tests.
		if _, err := pg.pool.Exec(ctx, `TRUNCATE audit_events, verification_decisions, telegraph_requests, spend_reservations, purchase_intents, delegations, agents, agent_challenges`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pg.Close)
		out["postgres"] = pg
	}
	return out
}

func seed(t *testing.T, s Store) (model.Agent, model.Delegation) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	a := model.Agent{ID: model.NewUUID(), AgentID: "agent_" + model.RandomToken(4), DeveloperLabel: "t", PublicKey: make([]byte, 32),
		KeyVersion: 1, Status: model.AgentActive, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateAgent(ctx, &a); err != nil {
		t.Fatal(err)
	}
	claims := model.DelegationClaims{DelegationID: model.NewID("dlg_"), SubjectAgentID: a.AgentID, MerchantID: "m1", Actions: []string{"purchase"},
		MaxAmountMinor: 500, Currency: "USD", IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		Issuer: "i", Audience: "a", ConsumerRef: "cr_1", IssuerKeyID: "k"}
	payload, _ := json.Marshal(claims)
	d := model.Delegation{ID: model.NewUUID(), Claims: claims, SignedPayload: payload, Signature: make([]byte, 64)}
	if err := s.CreateDelegation(ctx, d); err != nil {
		t.Fatal(err)
	}
	return a, d
}

func intent(a model.Agent, d model.Delegation, nonce string) *model.IntentRecord {
	return &model.IntentRecord{ID: model.NewUUID(), IntentID: model.NewID("pi_"), AgentID: a.AgentID, DelegationID: d.Claims.DelegationID,
		MerchantID: "m1", AmountMinor: 100, Currency: "USD", CartDigest: "sha256:x", Nonce: nonce, IntentHash: "h", ReceivedAt: time.Now().UTC()}
}

func TestStoreConformance(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			a, d := seed(t, s)

			t.Run("agent conflict and rotation", func(t *testing.T) {
				dup := a
				dup.ID = model.NewUUID()
				if err := s.CreateAgent(ctx, &dup); !errors.Is(err, ErrConflict) {
					t.Fatalf("dup agent: %v", err)
				}
				if _, err := s.RotateAgentKey(ctx, a.AgentID, 7, make([]byte, 32)); !errors.Is(err, ErrConflict) {
					t.Fatalf("stale version rotate: %v", err)
				}
			})

			t.Run("challenge single use", func(t *testing.T) {
				c := model.Challenge{ChallengeID: model.NewID("ch_"), AgentID: "x", Challenge: "c", Purpose: "register", ExpiresAt: time.Now().Add(time.Minute)}
				_ = s.CreateChallenge(ctx, c)
				if _, err := s.ConsumeChallenge(ctx, c.ChallengeID, time.Now()); err != nil {
					t.Fatal(err)
				}
				if _, err := s.ConsumeChallenge(ctx, c.ChallengeID, time.Now()); !errors.Is(err, ErrNotFound) {
					t.Fatalf("reuse: %v", err)
				}
			})

			t.Run("delegation signed payload round trip", func(t *testing.T) {
				got, err := s.GetDelegation(ctx, d.Claims.DelegationID)
				if err != nil || string(got.SignedPayload) != string(d.SignedPayload) {
					t.Fatalf("payload changed: %v\n%s\n%s", err, got.SignedPayload, d.SignedPayload)
				}
				if _, err := s.RevokeDelegation(ctx, d.Claims.DelegationID, "cr_other", time.Now()); !errors.Is(err, ErrNotFound) {
					t.Fatalf("revoke by non-owner: %v", err)
				}
			})

			t.Run("concurrent nonce replay", func(t *testing.T) {
				var ok atomic.Int32
				var wg sync.WaitGroup
				for range 16 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						if s.RecordIntent(ctx, intent(a, d, "same-nonce-0123456789")) == nil {
							ok.Add(1)
						}
					}()
				}
				wg.Wait()
				if ok.Load() != 1 {
					t.Fatalf("%d inserts accepted for one nonce", ok.Load())
				}
			})

			t.Run("concurrent cumulative reservation", func(t *testing.T) {
				limit := int64(300)
				var ok atomic.Int32
				var wg sync.WaitGroup
				for i := range 10 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						rec := intent(a, d, "res-nonce-"+model.RandomToken(8)+string(rune('a'+i)))
						if err := s.RecordIntent(ctx, rec); err != nil {
							t.Error(err)
							return
						}
						if s.ReserveSpend(ctx, d.Claims.DelegationID, rec.ID, 100, &limit) == nil {
							ok.Add(1)
						}
					}()
				}
				wg.Wait()
				if ok.Load() != 3 {
					t.Fatalf("%d reservations of 100 under limit 300", ok.Load())
				}
				got, _ := s.GetDelegation(ctx, d.Claims.DelegationID)
				if got.SpentMinor != 300 {
					t.Fatalf("spent %d", got.SpentMinor)
				}
			})

			t.Run("telegraph idempotency", func(t *testing.T) {
				rec := intent(a, d, "tg-nonce-"+model.RandomToken(8))
				_ = s.RecordIntent(ctx, rec)
				key := "tg:" + model.RandomToken(8)
				t1 := &model.TelegraphRecord{ID: model.NewUUID(), PurchaseIntentID: rec.ID, IdempotencyKey: key, IntentName: "I", Network: "n",
					SettlementStatus: model.EvidenceRequested, CreatedAt: time.Now().UTC()}
				if err := s.SaveTelegraph(ctx, t1); err != nil {
					t.Fatal(err)
				}
				t2 := *t1
				t2.ID = model.NewUUID()
				if err := s.SaveTelegraph(ctx, &t2); !errors.Is(err, ErrConflict) {
					t.Fatalf("second paid call for same key allowed: %v", err)
				}
				p := int64(10000)
				t1.PriceMinor, t1.SettlementStatus = &p, model.EvidenceSettled
				if err := s.SaveTelegraph(ctx, t1); err != nil {
					t.Fatal(err)
				}
				got, err := s.GetTelegraphByIdempotency(ctx, key)
				if err != nil || got.SettlementStatus != model.EvidenceSettled {
					t.Fatalf("%v %+v", err, got)
				}
				spent, _ := s.TelegraphSpendSince(ctx, time.Now().Add(-time.Hour))
				if spent < 10000 {
					t.Fatalf("spend %d", spent)
				}
			})

			t.Run("audit chain", func(t *testing.T) {
				var wg sync.WaitGroup
				for range 8 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						if _, err := s.AppendAudit(ctx, model.AuditEvent{EntityType: "t", EntityID: "x", EventType: "e", PayloadHash: "sha256:1"}); err != nil {
							t.Error(err)
						}
					}()
				}
				wg.Wait()
				all, _ := s.AllAudit(ctx)
				if len(all) != 8 || evidence.VerifyChain(all) != -1 {
					t.Fatalf("chain broken (%d events, first bad %d)", len(all), evidence.VerifyChain(all))
				}
			})
		})
	}
}
