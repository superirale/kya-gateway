// Package config loads KYA configuration from environment variables.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Mode            string // local | competition
	Addr            string
	DatabaseURL     string
	MerchantKeys    string
	AdminKey        string
	IssuerSeed      []byte
	IssuerKeyID     string
	SessionSecret   []byte
	DemoConsumers   string
	CORSOrigins     []string
	ClockSkew       time.Duration
	FailClosed      string // REVIEW | DENY
	AcceptSimulated bool
	RateLimitPerMin int
	Ephemeral       []string // which secrets were generated at boot (local only)

	TelegraphAdapter   string // simulated | x402
	TelegraphBaseURL   string
	TelegraphIntent    string
	TelegraphNetwork   string
	TelegraphAssets    []string
	TelegraphWalletKey string
	MaxPriceMinor      int64
	DailyCapMinor      int64
	MaxConcurrent      int
	TelegraphTimeout   time.Duration
	TelegraphRetries   int
	RPCURL             string
	ExplorerTxTemplate string
	TelegraphMinerID   string
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func envInt(k string, def int64) (int64, error) {
	v := env(k, "")
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", k, err)
	}
	return n, nil
}

func secretFromEnv(k string) (string, error) {
	if f := env(k+"_FILE", ""); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("%s_FILE: %w", k, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return env(k, ""), nil
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func Load() (Config, error) {
	c := Config{
		Mode:               env("KYA_MODE", "local"),
		Addr:               env("KYA_ADDR", ":8080"),
		DatabaseURL:        env("DATABASE_URL", ""),
		MerchantKeys:       env("KYA_MERCHANT_KEYS", ""),
		IssuerKeyID:        env("KYA_ISSUER_KID", "demo-issuer-1"),
		DemoConsumers:      env("KYA_DEMO_CONSUMERS", "alice:alice-demo-pass"),
		CORSOrigins:        split(env("KYA_CORS_ORIGINS", "http://localhost:5173")),
		FailClosed:         strings.ToUpper(env("KYA_FAIL_CLOSED_DECISION", "REVIEW")),
		TelegraphAdapter:   env("TELEGRAPH_ADAPTER", "simulated"),
		TelegraphBaseURL:   env("TELEGRAPH_BASE_URL", "https://devnode.telegraphprotocol.com"),
		TelegraphIntent:    env("TELEGRAPH_INTENT", "FRAUD_RISK_GENERAL"),
		TelegraphNetwork:   env("TELEGRAPH_NETWORK", "eip155:11155111"),
		TelegraphAssets:    split(env("TELEGRAPH_ALLOWED_ASSETS", "0xcc194e1a843B658526D0D5C431f670028582Ae17")),
		RPCURL:             env("SEPOLIA_RPC_URL", ""),
		ExplorerTxTemplate: env("TELEGRAPH_EXPLORER_TX_TEMPLATE", "https://sepolia.etherscan.io/tx/%s"),
		TelegraphMinerID:   env("TELEGRAPH_MINER_ID", ""),
	}
	var err error
	if c.AdminKey, err = secretFromEnv("KYA_ADMIN_KEY"); err != nil {
		return c, err
	}
	if c.TelegraphWalletKey, err = secretFromEnv("TELEGRAPH_WALLET_KEY"); err != nil {
		return c, err
	}
	seed, err := secretFromEnv("KYA_ISSUER_SEED")
	if err != nil {
		return c, err
	}
	if seed != "" {
		if c.IssuerSeed, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(seed, "=")); err != nil || len(c.IssuerSeed) != 32 {
			return c, errors.New("KYA_ISSUER_SEED must be 32 bytes base64url")
		}
	}
	sess, err := secretFromEnv("KYA_SESSION_SECRET")
	if err != nil {
		return c, err
	}
	c.SessionSecret = []byte(sess)

	skew, err := envInt("KYA_CLOCK_SKEW_SECONDS", 300)
	if err != nil {
		return c, err
	}
	c.ClockSkew = time.Duration(skew) * time.Second
	rl, err := envInt("KYA_RATE_LIMIT_PER_MIN", 120)
	if err != nil {
		return c, err
	}
	c.RateLimitPerMin = int(rl)
	if c.MaxPriceMinor, err = envInt("TELEGRAPH_MAX_PRICE_MINOR", 50_000); err != nil { // $0.05
		return c, err
	}
	if c.DailyCapMinor, err = envInt("TELEGRAPH_DAILY_CAP_MINOR", 2_000_000); err != nil { // $2.00
		return c, err
	}
	mc, err := envInt("TELEGRAPH_MAX_CONCURRENT", 2)
	if err != nil {
		return c, err
	}
	c.MaxConcurrent = int(mc)
	to, err := envInt("TELEGRAPH_TIMEOUT_SECONDS", 25)
	if err != nil {
		return c, err
	}
	c.TelegraphTimeout = time.Duration(to) * time.Second
	rt, err := envInt("TELEGRAPH_MAX_RETRIES", 2)
	if err != nil {
		return c, err
	}
	c.TelegraphRetries = int(rt)
	c.AcceptSimulated = env("KYA_ACCEPT_SIMULATED", "true") == "true"

	switch c.Mode {
	case "competition":
		// Competition mode: real evidence only, durable state, explicit secrets.
		c.AcceptSimulated = false
		if c.TelegraphAdapter != "x402" {
			return c, errors.New("competition mode requires TELEGRAPH_ADAPTER=x402 (no mock intelligence)")
		}
		if c.DatabaseURL == "" {
			return c, errors.New("competition mode requires DATABASE_URL")
		}
		if c.IssuerSeed == nil || len(c.SessionSecret) < 32 || c.MerchantKeys == "" {
			return c, errors.New("competition mode requires KYA_ISSUER_SEED, KYA_SESSION_SECRET (>=32 chars) and KYA_MERCHANT_KEYS")
		}
	case "local":
		if c.IssuerSeed == nil {
			c.IssuerSeed = randomBytes(32)
			c.Ephemeral = append(c.Ephemeral, "KYA_ISSUER_SEED")
		}
		if len(c.SessionSecret) == 0 {
			c.SessionSecret = randomBytes(32)
			c.Ephemeral = append(c.Ephemeral, "KYA_SESSION_SECRET")
		}
		if c.MerchantKeys == "" {
			c.MerchantKeys = "merchant_demo_001:local-demo-merchant-key-0001"
		}
	default:
		return c, fmt.Errorf("KYA_MODE must be local or competition, got %q", c.Mode)
	}
	if c.FailClosed != "REVIEW" && c.FailClosed != "DENY" {
		return c, errors.New("KYA_FAIL_CLOSED_DECISION must be REVIEW or DENY")
	}
	if c.TelegraphAdapter == "x402" && c.TelegraphWalletKey == "" {
		return c, errors.New("TELEGRAPH_ADAPTER=x402 requires TELEGRAPH_WALLET_KEY or TELEGRAPH_WALLET_KEY_FILE")
	}
	return c, nil
}
