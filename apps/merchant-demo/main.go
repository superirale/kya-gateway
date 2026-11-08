// Command merchant-demo is the demo merchant agent. It quotes carts, accepts a
// shopping agent's signed purchase intent, automatically calls KYA before
// completing a SIMULATED checkout, and proxies read-only KYA evidence for the
// dashboard (so the merchant API key never reaches a browser).
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/superirale/kya-gateway/internal/canonical"
	"github.com/superirale/kya-gateway/internal/model"
)

type product struct {
	SKU            string `json:"sku"`
	Name           string `json:"name"`
	Category       string `json:"category"`
	UnitPriceMinor int64  `json:"unit_price_minor"`
	Currency       string `json:"currency"`
}

var catalog = []product{
	{"sku_headphones_nc", "Noise-cancelling headphones", "electronics", 35000, "USD"},
	{"sku_smartwatch_pro", "Smartwatch Pro", "electronics", 65000, "USD"},
	{"sku_usb_c_cable", "USB-C cable (2m)", "accessories", 2500, "USD"},
}

type cartItem struct {
	SKU            string `json:"sku"`
	Quantity       int64  `json:"quantity"`
	UnitPriceMinor int64  `json:"unit_price_minor"`
}

// Cart is hashed canonically to produce intent.cart_digest.
type Cart struct {
	MerchantID string     `json:"merchant_id"`
	Items      []cartItem `json:"items"`
	Currency   string     `json:"currency"`
	TotalMinor int64      `json:"total_minor"`
}

type order struct {
	OrderID        string    `json:"order_id"`
	Status         string    `json:"status"` // SIMULATED_PAID | HELD_FOR_REVIEW | REJECTED
	Decision       string    `json:"decision"`
	VerificationID string    `json:"verification_id"`
	AgentID        string    `json:"agent_id"`
	Cart           Cart      `json:"cart"`
	PaymentNote    string    `json:"payment_note"`
	CreatedAt      time.Time `json:"created_at"`
}

type app struct {
	kyaURL, merchantID, apiKey string
	origins                    []string
	client                     *http.Client
	log                        *slog.Logger
	mu                         sync.Mutex
	orders                     []order
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	a := &app{
		kyaURL:     strings.TrimRight(env("KYA_URL", "http://localhost:8080"), "/"),
		merchantID: env("MERCHANT_ID", "merchant_demo_001"),
		apiKey:     env("MERCHANT_API_KEY", "local-demo-merchant-key-0001"),
		origins:    strings.Split(env("MERCHANT_CORS_ORIGINS", "http://localhost:5173"), ","),
		client:     &http.Client{Timeout: 60 * time.Second},
		log:        log,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /api/merchant", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"merchant_id": a.merchantID, "payment_mode": "SIMULATED"})
	})
	mux.HandleFunc("GET /api/catalog", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]any{"products": catalog}) })
	mux.HandleFunc("POST /api/quote", a.quote)
	mux.HandleFunc("POST /api/checkout", a.checkout)
	mux.HandleFunc("GET /api/orders", func(w http.ResponseWriter, _ *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		out := slices.Clone(a.orders)
		slices.Reverse(out)
		writeJSON(w, 200, map[string]any{"orders": out})
	})
	for _, p := range []string{"/verifications", "/verifications/{id}", "/verifications/{id}/evidence", "/stats", "/audit", "/audit/verify"} {
		mux.HandleFunc("GET /api/kya"+p, a.proxy)
	}
	addr := env("MERCHANT_ADDR", ":8081")
	log.Info("merchant demo listening", "addr", addr, "merchant_id", a.merchantID, "kya", a.kyaURL)
	srv := &http.Server{Addr: addr, Handler: a.cors(mux), ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Error("server", "err", err)
		os.Exit(1)
	}
}

func (a *app) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" && slices.Contains(a.origins, o) {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func (a *app) buildCart(sku string, qty int64) (Cart, string, product, bool) {
	i := slices.IndexFunc(catalog, func(p product) bool { return p.SKU == sku })
	if i < 0 || qty < 1 || qty > 10 {
		return Cart{}, "", product{}, false
	}
	p := catalog[i]
	c := Cart{MerchantID: a.merchantID, Currency: p.Currency, TotalMinor: p.UnitPriceMinor * qty,
		Items: []cartItem{{SKU: p.SKU, Quantity: qty, UnitPriceMinor: p.UnitPriceMinor}}}
	b, _ := canonical.Marshal(c)
	sum := sha256.Sum256(b)
	return c, "sha256:" + hex.EncodeToString(sum[:]), p, true
}

func (a *app) quote(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SKU      string `json:"sku"`
		Quantity int64  `json:"quantity"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		errJSON(w, 400, "MALFORMED_REQUEST", "bad JSON")
		return
	}
	cart, digest, p, ok := a.buildCart(req.SKU, req.Quantity)
	if !ok {
		errJSON(w, 422, "UNKNOWN_SKU", "unknown sku or bad quantity")
		return
	}
	writeJSON(w, 200, map[string]any{"cart": cart, "cart_digest": digest, "amount_minor": cart.TotalMinor, "currency": cart.Currency,
		"category": p.Category, "merchant_id": a.merchantID})
}

type signedIntent struct {
	AgentID      string `json:"agent_id"`
	MerchantID   string `json:"merchant_id"`
	DelegationID string `json:"delegation_id"`
	Intent       struct {
		AmountMinor int64  `json:"amount_minor"`
		Currency    string `json:"currency"`
		CartDigest  string `json:"cart_digest"`
	} `json:"intent"`
}

func (a *app) checkout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SKU           string          `json:"sku"`
		Quantity      int64           `json:"quantity"`
		SignedRequest json.RawMessage `json:"signed_request"`
		Simulate      string          `json:"simulate,omitempty"` // local demo only; forwarded to KYA
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || len(req.SignedRequest) == 0 {
		errJSON(w, 400, "MALFORMED_REQUEST", "sku, quantity and signed_request required")
		return
	}
	cart, digest, _, ok := a.buildCart(req.SKU, req.Quantity)
	if !ok {
		errJSON(w, 422, "UNKNOWN_SKU", "unknown sku or bad quantity")
		return
	}
	var si signedIntent
	if json.Unmarshal(req.SignedRequest, &si) != nil {
		errJSON(w, 400, "MALFORMED_REQUEST", "signed_request is not valid JSON")
		return
	}
	// Merchant-side binding: the agent must have signed THIS cart and total.
	if si.MerchantID != a.merchantID || si.Intent.CartDigest != digest || si.Intent.AmountMinor != cart.TotalMinor || si.Intent.Currency != cart.Currency {
		errJSON(w, 422, "CART_MISMATCH", "signed intent does not match this merchant's cart (digest, amount or currency)")
		return
	}

	// Merchant agent automatically calls KYA before taking (simulated) payment.
	hreq, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, a.kyaURL+"/v1/verify-transactions", bytes.NewReader(req.SignedRequest))
	hreq.Header.Set("Authorization", "Bearer "+a.apiKey)
	hreq.Header.Set("Content-Type", "application/json")
	if req.Simulate != "" {
		hreq.Header.Set("X-KYA-Simulate", req.Simulate)
	}
	resp, err := a.client.Do(hreq)
	if err != nil {
		errJSON(w, 502, "KYA_UNREACHABLE", "verification service unreachable; checkout not completed")
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var verdict map[string]any
	if json.Unmarshal(body, &verdict) != nil {
		errJSON(w, 502, "KYA_BAD_RESPONSE", "unparseable verification response")
		return
	}
	decision, _ := verdict["decision"].(string)
	if decision == "" { // KYA rejected the request itself (4xx): pass the error through
		writeJSON(w, resp.StatusCode, map[string]any{"verification": verdict, "order": nil})
		return
	}
	o := order{OrderID: model.NewID("ord_"), Decision: decision, AgentID: si.AgentID, Cart: cart, CreatedAt: time.Now().UTC()}
	o.VerificationID, _ = verdict["verification_id"].(string)
	switch decision {
	case "ALLOW":
		o.Status, o.PaymentNote = "SIMULATED_PAID", "SIMULATED checkout: no real payment was taken"
	case "REVIEW":
		o.Status, o.PaymentNote = "HELD_FOR_REVIEW", "Order held for manual risk review; no payment taken"
	default:
		o.Status, o.PaymentNote = "REJECTED", "Order rejected by KYA decision"
	}
	a.mu.Lock()
	a.orders = append(a.orders, o)
	if len(a.orders) > 500 {
		a.orders = a.orders[1:]
	}
	a.mu.Unlock()
	a.log.Info("checkout", "order_id", o.OrderID, "decision", decision, "verification_id", o.VerificationID)
	writeJSON(w, 200, map[string]any{"verification": verdict, "order": o})
}

// proxy forwards read-only evidence requests to KYA with the merchant key.
func (a *app) proxy(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/kya")
	u := a.kyaURL + "/v1" + path
	if q := r.URL.RawQuery; q != "" {
		u += "?" + q
	}
	hreq, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, u, nil)
	hreq.Header.Set("Authorization", "Bearer "+a.apiKey)
	resp, err := a.client.Do(hreq)
	if err != nil {
		errJSON(w, 502, "KYA_UNREACHABLE", "verification service unreachable")
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 4<<20))
}
