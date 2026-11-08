package telegraph

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ProbeResult describes the live payment challenge for an intent. Probing
// sends an UNPAID request: nothing is signed and nothing is spent.
type ProbeResult struct {
	HTTPStatus  int               `json:"http_status"`
	X402Version int               `json:"x402_version"`
	Accepts     []json.RawMessage `json:"accepts"`
	Usable      bool              `json:"usable"`
	Problems    []string          `json:"problems,omitempty"`
	Body        string            `json:"body,omitempty"`
}

// Probe performs the unpaid first leg of the x402 flow and checks the
// challenge against this client's network, asset allowlist and price cap.
func (c *X402Client) Probe(ctx context.Context, subject string) (ProbeResult, error) {
	return ProbeChallenge(ctx, c.cfg.HTTP, c.cfg.BaseURL, c.cfg.Intent, c.cfg.Network, c.cfg.AllowedAssets, c.cfg.MaxPriceMinor, subject)
}

func ProbeChallenge(ctx context.Context, hc *http.Client, baseURL, intent, network string, assets []string, maxPrice int64, subject string) (ProbeResult, error) {
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	body, _ := json.Marshal(map[string]any{"intent": intent, "params": map[string]string{"subject": subject}})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/engine/v1/ask", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "kya-gateway/1.0 (probe)")
	resp, err := hc.Do(req)
	if err != nil {
		return ProbeResult{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	out := ProbeResult{HTTPStatus: resp.StatusCode}
	if resp.StatusCode != http.StatusPaymentRequired {
		out.Body = snippet(b)
		out.Problems = append(out.Problems, fmt.Sprintf("expected HTTP 402, got %d", resp.StatusCode))
		return out, nil
	}
	var ch paymentChallenge
	if err := decodeB64JSON(resp.Header.Get("PAYMENT-REQUIRED"), &ch); err != nil {
		out.Problems = append(out.Problems, "PAYMENT-REQUIRED header missing or not base64 JSON")
		return out, nil
	}
	out.X402Version, out.Accepts = ch.X402Version, ch.Accepts
	for _, a := range ch.Accepts {
		var pr paymentRequirement
		if json.Unmarshal(a, &pr) != nil {
			continue
		}
		var why []string
		if pr.Scheme != "exact" {
			why = append(why, "scheme "+pr.Scheme)
		}
		if pr.Network != network {
			why = append(why, "network "+pr.Network)
		}
		allowed := false
		for _, x := range assets {
			allowed = allowed || strings.EqualFold(x, pr.Asset)
		}
		if !allowed {
			why = append(why, "asset "+pr.Asset+" not allowlisted")
		}
		amt := pr.Amount
		if amt == "" {
			amt = pr.MaxAmountRequired
		}
		var n int64
		if _, err := fmt.Sscan(amt, &n); err != nil || n <= 0 {
			why = append(why, "bad amount "+amt)
		} else if n > maxPrice {
			why = append(why, fmt.Sprintf("price %d > cap %d", n, maxPrice))
		}
		if extraString(pr.Extra, "name") == "" || extraString(pr.Extra, "version") == "" {
			why = append(why, "missing EIP-712 name/version")
		}
		if len(why) == 0 {
			out.Usable = true
		} else {
			out.Problems = append(out.Problems, strings.Join(why, ", "))
		}
	}
	return out, nil
}
