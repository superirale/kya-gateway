// Command api runs the KYA Gateway HTTP service.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/superirale/kya-gateway/internal/api"
	"github.com/superirale/kya-gateway/internal/auth"
	"github.com/superirale/kya-gateway/internal/config"
	"github.com/superirale/kya-gateway/internal/delegation"
	"github.com/superirale/kya-gateway/internal/model"
	"github.com/superirale/kya-gateway/internal/policy"
	"github.com/superirale/kya-gateway/internal/service"
	"github.com/superirale/kya-gateway/internal/storage"
	"github.com/superirale/kya-gateway/internal/telegraph"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var store storage.Store
	if cfg.DatabaseURL != "" {
		pg, err := storage.OpenPostgres(ctx, cfg.DatabaseURL)
		if err != nil {
			return err
		}
		defer pg.Close()
		store = pg
		log.Info("storage", "backend", "postgres")
	} else {
		store = storage.NewMemory()
		log.Warn("storage", "backend", "memory", "note", "state is lost on restart; set DATABASE_URL for durability")
	}
	if len(cfg.Ephemeral) > 0 {
		log.Warn("ephemeral secrets generated (local mode only); sessions/delegations will not survive restart", "secrets", cfg.Ephemeral)
	}

	issuer, err := delegation.NewIssuer(cfg.IssuerKeyID, cfg.IssuerSeed)
	if err != nil {
		return err
	}

	pol := policy.DefaultConfig()
	pol.FailClosedDecision = model.Decision(cfg.FailClosed)
	pol.AcceptSimulated = cfg.AcceptSimulated

	var intel telegraph.IntelligenceClient
	var budget *telegraph.DailyBudget
	switch cfg.TelegraphAdapter {
	case "x402":
		wallet, err := telegraph.ParseWallet(cfg.TelegraphWalletKey)
		if err != nil {
			return err
		}
		cfg.TelegraphWalletKey = "" // drop the plaintext copy
		midnight := time.Now().UTC().Truncate(24 * time.Hour)
		spent, err := store.TelegraphSpendSince(ctx, midnight)
		if err != nil {
			return err
		}
		budget = telegraph.NewDailyBudget(cfg.DailyCapMinor, cfg.MaxConcurrent, spent)
		intel, err = telegraph.NewX402Client(telegraph.X402Config{
			BaseURL: cfg.TelegraphBaseURL, Intent: cfg.TelegraphIntent, Network: cfg.TelegraphNetwork,
			AllowedAssets: cfg.TelegraphAssets, MaxPriceMinor: cfg.MaxPriceMinor, Timeout: cfg.TelegraphTimeout,
			MaxRetries: cfg.TelegraphRetries, RPCURL: cfg.RPCURL, ExplorerTxTemplate: cfg.ExplorerTxTemplate,
			Wallet: wallet, Budget: budget, MinerID: cfg.TelegraphMinerID,
		})
		if err != nil {
			return err
		}
		log.Info("telegraph", "adapter", "x402", "intent", cfg.TelegraphIntent, "network", cfg.TelegraphNetwork,
			"payer", wallet.Address(), "max_price_minor", cfg.MaxPriceMinor, "daily_cap_minor", cfg.DailyCapMinor, "spent_today_minor", spent)
	case "simulated":
		if cfg.Mode == "competition" {
			return errors.New("simulated adapter forbidden in competition mode")
		}
		intel = &telegraph.SimulatedClient{Intent: cfg.TelegraphIntent, Latency: 150 * time.Millisecond}
		log.Warn("telegraph", "adapter", "simulated", "note", "SIMULATED intelligence; no Telegraph purchases are made")
	default:
		return errors.New("TELEGRAPH_ADAPTER must be simulated or x402")
	}

	merchants, err := auth.ParseMerchantKeys(cfg.MerchantKeys)
	if err != nil {
		return err
	}
	svc := &service.Service{Store: store, Issuer: issuer, Intel: intel, Policy: pol, Mode: cfg.Mode, ClockSkew: cfg.ClockSkew, Log: log}
	srv := &api.Server{
		Svc: svc, Merchants: merchants, AdminKey: cfg.AdminKey, Consumers: auth.ParseConsumers(cfg.DemoConsumers),
		Sessions: auth.NewSessions(cfg.SessionSecret, 2*time.Hour), CORSOrigins: cfg.CORSOrigins,
		RatePerMin: cfg.RateLimitPerMin, Budget: budget, Log: log,
	}
	hs := &http.Server{Addr: cfg.Addr, Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	log.Info("kya api listening", "addr", cfg.Addr, "mode", cfg.Mode, "policy_version", pol.Version)
	if err := hs.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
