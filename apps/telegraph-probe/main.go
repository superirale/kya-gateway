// Command telegraph-probe is the integration-spike tool (backlog H01).
//
//	telegraph-probe            # UNPAID: fetch and validate the live 402 challenge
//	telegraph-probe -pay       # PAID: one real purchase + receipt verification
//	                           # (requires TELEGRAPH_WALLET_KEY[_FILE]; spends <= TELEGRAPH_MAX_PRICE_MINOR)
//
// Uses the same environment variables as the API (see .env.example). Output is
// JSON suitable for docs/telegraph-integration.md evidence (no secrets).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/superirale/kya-gateway/internal/config"
	"github.com/superirale/kya-gateway/internal/telegraph"
)

func main() {
	pay := flag.Bool("pay", false, "make one REAL paid request (spends testnet USDC)")
	balance := flag.Bool("balance", false, "show the wallet's Sepolia ETH and test-USDC balances")
	mint := flag.Float64("mint", 0, "mint this many TEST USDC to the wallet (Sepolia only; costs a little Sepolia ETH gas)")
	flag.Parse()
	_ = os.Setenv("KYA_MODE", "local") // probe never needs competition secrets
	_ = os.Setenv("TELEGRAPH_ADAPTER", "simulated")
	cfg, err := config.Load()
	if err != nil {
		fail(err)
	}
	if *balance || *mint > 0 {
		walletOps(cfg, *mint)
		return
	}
	req := telegraph.RiskRequest{MerchantRef: "m_probe", AmountBucket: "USD_250_500", Currency: "USD", Action: "purchase",
		Category: "electronics", AgentKeyAge: "lt_1d", DelegationAge: "lt_1h", DelegationUsage: "50_75pct"}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if !*pay {
		res, err := telegraph.ProbeChallenge(ctx, nil, cfg.TelegraphBaseURL, cfg.TelegraphIntent, cfg.TelegraphNetwork, cfg.TelegraphAssets, cfg.MaxPriceMinor, req.Subject())
		if err != nil {
			fail(err)
		}
		print(map[string]any{"mode": "unpaid-probe", "base_url": cfg.TelegraphBaseURL, "intent": cfg.TelegraphIntent, "result": res})
		if !res.Usable {
			os.Exit(2)
		}
		return
	}

	wallet, err := telegraph.ParseWallet(cfg.TelegraphWalletKey)
	if err != nil {
		fail(err)
	}
	budget := telegraph.NewDailyBudget(cfg.MaxPriceMinor, 1, 0) // exactly one call's worth
	c, err := telegraph.NewX402Client(telegraph.X402Config{BaseURL: cfg.TelegraphBaseURL, Intent: cfg.TelegraphIntent, Network: cfg.TelegraphNetwork,
		AllowedAssets: cfg.TelegraphAssets, MaxPriceMinor: cfg.MaxPriceMinor, Timeout: cfg.TelegraphTimeout, MaxRetries: cfg.TelegraphRetries,
		RPCURL: cfg.RPCURL, ExplorerTxTemplate: cfg.ExplorerTxTemplate, Wallet: wallet, Budget: budget, MinerID: cfg.TelegraphMinerID})
	if err != nil {
		fail(err)
	}
	ev, perr := c.PurchaseRisk(ctx, req)
	out := map[string]any{"mode": "paid", "payer": wallet.Address(), "evidence": ev, "observed_at": time.Now().UTC()}
	if perr != nil {
		out["error"] = perr.Error()
	} else {
		st, _ := c.VerifyEvidence(ctx, ev)
		out["verification"] = st
	}
	print(out)
	if perr != nil {
		os.Exit(1)
	}
}

// walletOps shows balances and optionally mints test USDC (permissionless
// mint(address,uint256) on the Telegraph test token, verified via eth_estimateGas).
func walletOps(cfg config.Config, mintUSDC float64) {
	if cfg.TelegraphWalletKey == "" {
		fail(fmt.Errorf("set TELEGRAPH_WALLET_KEY_FILE (or TELEGRAPH_WALLET_KEY)"))
	}
	if cfg.RPCURL == "" {
		fail(fmt.Errorf("set SEPOLIA_RPC_URL"))
	}
	if cfg.TelegraphNetwork != "eip155:11155111" || len(cfg.TelegraphAssets) == 0 {
		fail(fmt.Errorf("minting is only supported for the Sepolia test token"))
	}
	wallet, err := telegraph.ParseWallet(cfg.TelegraphWalletKey)
	if err != nil {
		fail(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	rpc := telegraph.RPC{URL: cfg.RPCURL}
	asset := cfg.TelegraphAssets[0]
	show := func() {
		eth, err1 := rpc.ETHBalance(ctx, wallet.Address())
		usdc, err2 := rpc.TokenBalance(ctx, asset, wallet.Address())
		if err1 != nil || err2 != nil {
			fail(fmt.Errorf("balance lookup failed: %v %v", err1, err2))
		}
		ethF, _ := new(big.Float).Quo(new(big.Float).SetInt(eth), big.NewFloat(1e18)).Float64()
		usdcF, _ := new(big.Float).Quo(new(big.Float).SetInt(usdc), big.NewFloat(1e6)).Float64()
		fmt.Printf("wallet %s\n  Sepolia ETH: %.6f\n  test USDC:   %.6f\n", wallet.Address(), ethF, usdcF)
	}
	show()
	if mintUSDC <= 0 {
		return
	}
	if mintUSDC > 1000 {
		fail(fmt.Errorf("refusing to mint more than 1000 test USDC at once"))
	}
	amount := big.NewInt(int64(mintUSDC * 1e6))
	data, err := telegraph.MintCalldata(wallet.Address(), amount)
	if err != nil {
		fail(err)
	}
	fmt.Printf("minting %.6f test USDC… (waiting for confirmation)\n", mintUSDC)
	tx, err := rpc.SendContractCall(ctx, wallet, asset, data)
	if tx != "" {
		fmt.Printf("  tx: "+cfg.ExplorerTxTemplate+"\n", tx)
	}
	if err != nil {
		fail(err)
	}
	show()
}

func print(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
