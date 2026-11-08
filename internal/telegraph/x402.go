package telegraph

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/superirale/kya-gateway/internal/model"
)

// X402Config configures the real Telegraph testnet adapter. Field names and
// flow follow the Telegraph engine docs (anjoman.ai/docs, "Using" section);
// see docs/telegraph-integration.md for what is confirmed vs. assumed.
type X402Config struct {
	BaseURL            string        // e.g. https://devnode.telegraphprotocol.com
	Intent             string        // e.g. FRAUD_RISK_GENERAL
	Network            string        // CAIP-2, e.g. eip155:11155111
	AllowedAssets      []string      // token contracts we are willing to pay with
	MaxPriceMinor      int64         // per-call cap in asset base units (micro-USDC)
	Timeout            time.Duration // whole-purchase deadline
	MaxRetries         int
	RPCURL             string // Sepolia JSON-RPC for independent tx verification
	ExplorerTxTemplate string // e.g. https://sepolia.etherscan.io/tx/%s
	MinerID            string // optional: pin requests to one miner (/engine/v1/ask/{id})
	Wallet             *Wallet
	Budget             Budget
	HTTP               *http.Client
}

type X402Client struct{ cfg X402Config }

func NewX402Client(cfg X402Config) (*X402Client, error) {
	if cfg.BaseURL == "" || cfg.Intent == "" || cfg.Wallet == nil {
		return nil, errors.New("telegraph: base URL, intent and wallet are required")
	}
	if cfg.MaxPriceMinor <= 0 {
		return nil, errors.New("telegraph: per-call price cap required")
	}
	if len(cfg.AllowedAssets) == 0 {
		return nil, errors.New("telegraph: at least one allowed payment asset required")
	}
	if cfg.Network == "" {
		cfg.Network = "eip155:11155111"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 25 * time.Second
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 20 * time.Second}
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &X402Client{cfg: cfg}, nil
}

func (c *X402Client) Describe() Description {
	return Description{
		Adapter: "telegraph-x402", Network: c.cfg.Network, Intent: c.cfg.Intent, BaseURL: c.cfg.BaseURL,
		PayerAddress: c.cfg.Wallet.Address(), MaxPriceMinor: c.cfg.MaxPriceMinor, PriceCurrency: "USDC",
	}
}

// paymentRequirement is one entry of the 402 challenge's accepts[]. Raw is
// echoed back verbatim as "accepted" in the payment payload.
type paymentRequirement struct {
	Scheme            string         `json:"scheme"`
	Network           string         `json:"network"`
	Asset             string         `json:"asset"`
	Amount            string         `json:"amount"`
	MaxAmountRequired string         `json:"maxAmountRequired"` // x402 v1 name
	PayTo             string         `json:"payTo"`
	MaxTimeoutSeconds int64          `json:"maxTimeoutSeconds"`
	Extra             map[string]any `json:"extra"`
	raw               json.RawMessage
}

type paymentChallenge struct {
	X402Version int               `json:"x402Version"`
	Resource    json.RawMessage   `json:"resource,omitempty"`
	Accepts     []json.RawMessage `json:"accepts"`
	Error       string            `json:"error,omitempty"`
}

func decodeB64JSON(s string, v any) error {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return json.Unmarshal(b, v)
		}
	}
	return errors.New("not base64 JSON")
}

func (c *X402Client) PurchaseRisk(ctx context.Context, req RiskRequest) (RiskEvidence, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	start := time.Now()
	ev := RiskEvidence{Intent: c.cfg.Intent, Network: c.cfg.Network, State: model.EvidenceRequested, Payer: c.cfg.Wallet.Address()}
	body, _ := json.Marshal(map[string]any{"intent": c.cfg.Intent, "params": map[string]string{"subject": req.Subject()}})
	url := c.cfg.BaseURL + "/engine/v1/ask"
	if c.cfg.MinerID != "" {
		url += "/" + c.cfg.MinerID // direct to one miner (canonical intent+params form)
	}

	// 1. Unpaid request -> expect 402 challenge. Safe to retry: nothing is paid.
	resp, respBody, err := c.doWithRetry(ctx, url, body, nil)
	if err != nil {
		return c.fail(ev, start, err)
	}
	if resp.StatusCode != http.StatusPaymentRequired {
		return c.fail(ev, start, classifyStatus(resp.StatusCode, respBody, false))
	}
	header, accepted, amount, err := c.buildPayment(resp)
	if err != nil {
		return c.fail(ev, start, err)
	}
	ev.Asset, ev.PayTo = accepted.Asset, accepted.PayTo

	// 2. Spend guard before signing anything.
	commit, err := c.cfg.Budget.Reserve(amount)
	if err != nil {
		return c.fail(ev, start, &Error{Code: ErrCodeSpendCap, Msg: err.Error()})
	}
	spent := false
	defer func() { commit(spent) }()

	// 3. Paid request. Retrying with the SAME signed authorization is
	// idempotent: an EIP-3009 nonce can only be settled once on chain.
	resp, respBody, err = c.doWithRetry(ctx, url, body, header)
	if err != nil {
		spent = true // payment may have settled; account for it conservatively
		var te *Error
		if errors.As(err, &te) {
			te.Paid = true
		}
		return c.fail(ev, start, err)
	}
	switch {
	case resp.StatusCode == http.StatusOK:
		spent = true
	case resp.StatusCode == http.StatusPaymentRequired:
		return c.fail(ev, start, &Error{Code: ErrCodePayment, Msg: "payment authorization not accepted"})
	case resp.StatusCode == http.StatusUnprocessableEntity:
		return c.fail(ev, start, &Error{Code: ErrCodeSchema, Msg: "pre-request validation failed (not charged): " + snippet(respBody)})
	default:
		spent = resp.StatusCode >= 500 // engine credits escrow when the miner fails after settlement
		return c.fail(ev, start, classifyStatus(resp.StatusCode, respBody, spent))
	}

	ev.LatencyMs = int(time.Since(start).Milliseconds())
	if err := c.parseDelivered(&ev, resp, respBody, amount); err != nil {
		ev.State = model.EvidenceUnverified
		ev.ErrorCode = codeOf(err)
		ev.Note = err.Error()
		return ev, err
	}
	return ev, nil
}

func (c *X402Client) fail(ev RiskEvidence, start time.Time, err error) (RiskEvidence, error) {
	ev.State = model.EvidenceFailed
	ev.ErrorCode = codeOf(err)
	ev.Note = err.Error()
	ev.LatencyMs = int(time.Since(start).Milliseconds())
	if errors.Is(err, context.DeadlineExceeded) {
		ev.ErrorCode = ErrCodeTimeout
	}
	return ev, err
}

func (c *X402Client) buildPayment(resp *http.Response) (http.Header, paymentRequirement, int64, error) {
	var ch paymentChallenge
	raw := resp.Header.Get("PAYMENT-REQUIRED")
	if raw == "" {
		return nil, paymentRequirement{}, 0, &Error{Code: ErrCodeBadChallenge, Msg: "402 without PAYMENT-REQUIRED header"}
	}
	if err := decodeB64JSON(raw, &ch); err != nil {
		return nil, paymentRequirement{}, 0, &Error{Code: ErrCodeBadChallenge, Msg: "undecodable PAYMENT-REQUIRED"}
	}
	var chosen *paymentRequirement
	for _, a := range ch.Accepts {
		var pr paymentRequirement
		if json.Unmarshal(a, &pr) != nil {
			continue
		}
		pr.raw = a
		if pr.Scheme == "exact" && pr.Network == c.cfg.Network && c.assetAllowed(pr.Asset) {
			chosen = &pr
			break
		}
	}
	if chosen == nil {
		return nil, paymentRequirement{}, 0, &Error{Code: ErrCodeBadChallenge, Msg: "no acceptable exact/" + c.cfg.Network + " payment option for an allowed asset"}
	}
	amountStr := chosen.Amount
	if amountStr == "" {
		amountStr = chosen.MaxAmountRequired
	}
	amount, err := strconv.ParseInt(amountStr, 10, 64)
	if err != nil || amount <= 0 {
		return nil, paymentRequirement{}, 0, &Error{Code: ErrCodeBadChallenge, Msg: "invalid amount"}
	}
	if amount > c.cfg.MaxPriceMinor {
		return nil, paymentRequirement{}, 0, &Error{Code: ErrCodePriceCap, Msg: fmt.Sprintf("price %d exceeds per-call cap %d", amount, c.cfg.MaxPriceMinor)}
	}
	if _, err := parseAddress(chosen.PayTo); err != nil {
		return nil, paymentRequirement{}, 0, &Error{Code: ErrCodeBadChallenge, Msg: "invalid payTo"}
	}
	chainID, err := chainIDFromCAIP2(chosen.Network)
	if err != nil {
		return nil, paymentRequirement{}, 0, &Error{Code: ErrCodeBadChallenge, Msg: err.Error()}
	}
	timeout := chosen.MaxTimeoutSeconds
	if timeout <= 0 || timeout > 600 {
		timeout = 60
	}
	now := time.Now().Unix()
	auth := TransferAuthorization{
		From: c.cfg.Wallet.Address(), To: chosen.PayTo, Value: strconv.FormatInt(amount, 10),
		ValidAfter: strconv.FormatInt(now-600, 10), ValidBefore: strconv.FormatInt(now+timeout, 10),
		Nonce: randomNonce32(),
	}
	name, version := extraString(chosen.Extra, "name"), extraString(chosen.Extra, "version")
	if name == "" || version == "" {
		return nil, paymentRequirement{}, 0, &Error{Code: ErrCodeBadChallenge, Msg: "challenge missing EIP-712 domain name/version"}
	}
	digest, err := TransferDigest(EIP712Domain{Name: name, Version: version, ChainID: chainID, VerifyingContract: chosen.Asset}, auth)
	if err != nil {
		return nil, paymentRequirement{}, 0, &Error{Code: ErrCodeBadChallenge, Msg: err.Error()}
	}
	sig := "0x" + hex.EncodeToString(c.cfg.Wallet.SignHash(digest))
	inner := map[string]any{"signature": sig, "authorization": auth}
	h := http.Header{}
	if ch.X402Version >= 2 {
		payload := map[string]any{"x402Version": ch.X402Version, "accepted": chosen.raw, "payload": inner}
		if len(ch.Resource) > 0 {
			payload["resource"] = ch.Resource
		}
		b, _ := json.Marshal(payload)
		h.Set("PAYMENT-SIGNATURE", base64.StdEncoding.EncodeToString(b))
	} else {
		b, _ := json.Marshal(map[string]any{"x402Version": 1, "scheme": chosen.Scheme, "network": chosen.Network, "payload": inner})
		h.Set("X-PAYMENT", base64.StdEncoding.EncodeToString(b))
	}
	return h, *chosen, amount, nil
}

func (c *X402Client) assetAllowed(a string) bool {
	for _, x := range c.cfg.AllowedAssets {
		if strings.EqualFold(x, a) {
			return true
		}
	}
	return false
}

func chainIDFromCAIP2(n string) (*big.Int, error) {
	ns, ref, ok := strings.Cut(n, ":")
	if !ok || ns != "eip155" {
		return nil, fmt.Errorf("unsupported network %q", n)
	}
	id, ok := new(big.Int).SetString(ref, 10)
	if !ok {
		return nil, fmt.Errorf("bad chain id in %q", n)
	}
	return id, nil
}

func (c *X402Client) doWithRetry(ctx context.Context, url string, body []byte, extra http.Header) (*http.Response, []byte, error) {
	var lastErr error
	for attempt := 0; attempt <= c.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(250*(1<<(attempt-1))) * time.Millisecond
			select {
			case <-ctx.Done():
				return nil, nil, &Error{Code: ErrCodeTimeout, Msg: ctx.Err().Error()}
			case <-time.After(backoff):
			}
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "kya-gateway/1.0")
		for k, v := range extra {
			req.Header[k] = v
		}
		resp, err := c.cfg.HTTP.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, &Error{Code: ErrCodeTimeout, Msg: "request deadline exceeded"}
			}
			lastErr = &Error{Code: ErrCodeUnavailable, Msg: "transport error"}
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 502 && resp.StatusCode <= 504 && !bytes.Contains(b, []byte("no_compatible_miner"))) {
			lastErr = classifyStatus(resp.StatusCode, b, false)
			continue
		}
		return resp, b, nil
	}
	return nil, nil, lastErr
}

func classifyStatus(code int, body []byte, paid bool) error {
	switch {
	case bytes.Contains(body, []byte("no_compatible_miner")):
		return &Error{Code: ErrCodeNoMiner, Msg: "no compatible miner for intent", Paid: paid}
	case code == http.StatusBadRequest:
		return &Error{Code: ErrCodeSchema, Msg: "request rejected: " + snippet(body), Paid: paid}
	case code == http.StatusTooManyRequests, code >= 500:
		return &Error{Code: ErrCodeUnavailable, Msg: fmt.Sprintf("HTTP %d", code), Paid: paid}
	}
	return &Error{Code: ErrCodeHTTP, Msg: fmt.Sprintf("unexpected HTTP %d", code), Paid: paid}
}

func snippet(b []byte) string {
	s := strings.Map(func(r rune) rune {
		if r < 0x20 {
			return ' '
		}
		return r
	}, string(b))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// askResponse mirrors the documented 200 body of /engine/v1/ask.
type askResponse struct {
	MinerID     json.RawMessage `json:"miner_id"`
	MinerName   string          `json:"miner_name"`
	Result      json.RawMessage `json:"result"`
	ResultShape string          `json:"result_shape"`
	CostUSD     json.Number     `json:"cost_usd"`
	Intent      string          `json:"intent"`
	SignalHash  string          `json:"signal_hash"`
	FieldStatus json.RawMessage `json:"field_status"`
}

type receipt struct {
	ReceiptHash string          `json:"receipt_hash"`
	Rail        string          `json:"rail"`
	Payer       string          `json:"payer"`
	Miner       json.RawMessage `json:"miner"`
	Intent      string          `json:"intent"`
	AmountUUSDC string          `json:"amount_uusdc"`
	Settlement  string          `json:"settlement"`
	Chain       json.RawMessage `json:"chain"`
	TxHash      string          `json:"tx_hash"`
	Timestamp   int64           `json:"timestamp"`
}

var (
	levelPattern  = regexp.MustCompile(`^[A-Z_]{2,32}$`)
	txHashPattern = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)
	hashPattern   = regexp.MustCompile(`^(0x)?[0-9a-fA-F]{64}$`)
)

func (c *X402Client) parseDelivered(ev *RiskEvidence, resp *http.Response, body []byte, authorized int64) error {
	var ar askResponse
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&ar); err != nil {
		return &Error{Code: ErrCodeSchema, Msg: "undecodable response body", Paid: true}
	}
	if ar.Intent != "" && ar.Intent != c.cfg.Intent {
		return &Error{Code: ErrCodeSchema, Msg: fmt.Sprintf("response intent %q != requested %q", ar.Intent, c.cfg.Intent), Paid: true}
	}
	if hashPattern.MatchString(ar.SignalHash) {
		ev.RequestID = ar.SignalHash
	}
	if id := strings.Trim(string(ar.MinerID), `"`); id != "" && id != "null" {
		ev.ProviderID = &id
	}
	if ar.MinerName != "" {
		n := ar.MinerName
		ev.ProviderName = &n
	}
	ev.Result = sanitizeResult(ar.Result)
	if len(ar.Result) > 0 {
		sum := sha256.Sum256(ar.Result)
		h := "sha256:" + hex.EncodeToString(sum[:])
		ev.ResultHash = &h
	}
	ev.RiskLevel, ev.RiskScore = extractRisk(ar.Result)

	if rh := resp.Header.Get("X-TELEGRAPH-RECEIPT"); rh != "" {
		var r receipt
		if err := decodeB64JSON(rh, &r); err == nil {
			ev.Receipt, _ = json.Marshal(r)
			if r.ReceiptHash != "" {
				v := r.ReceiptHash
				ev.ReceiptID = &v
			}
			if txHashPattern.MatchString(r.TxHash) {
				v := r.TxHash
				ev.TxHash = &v
			}
			if n, err := strconv.ParseInt(r.AmountUUSDC, 10, 64); err == nil {
				ev.PriceMinor = &n
				cur := "USDC"
				ev.PriceCurrency = &cur
			}
			if r.Payer != "" && !strings.EqualFold(r.Payer, ev.Payer) {
				ev.Note = "receipt payer differs from configured wallet"
			}
		}
	}
	if ev.TxHash == nil {
		var pr struct {
			Transaction string `json:"transaction"`
			TxHash      string `json:"txHash"`
		}
		if decodeB64JSON(resp.Header.Get("PAYMENT-RESPONSE"), &pr) == nil {
			for _, t := range []string{pr.Transaction, pr.TxHash} {
				if txHashPattern.MatchString(t) {
					v := t
					ev.TxHash = &v
					break
				}
			}
		}
	}
	if ev.PriceMinor == nil { // fall back to the amount we actually authorized
		n := authorized
		ev.PriceMinor = &n
		cur := "USDC"
		ev.PriceCurrency = &cur
	}
	if ev.TxHash != nil && c.cfg.ExplorerTxTemplate != "" {
		u := fmt.Sprintf(c.cfg.ExplorerTxTemplate, *ev.TxHash)
		ev.ExplorerURL = &u
	}
	return nil
}

// extractRisk reads only an enum-like level and a finite numeric score.
// Anything else in the provider result is never interpreted.
func extractRisk(raw json.RawMessage) (string, *float64) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return "", nil
	}
	level := ""
	for _, k := range []string{"risk_level", "verdict"} {
		var s string
		if json.Unmarshal(m[k], &s) == nil {
			s = strings.ToUpper(strings.TrimSpace(s))
			if levelPattern.MatchString(s) {
				level = s
				break
			}
		}
	}
	var score *float64
	var n json.Number
	d := json.NewDecoder(bytes.NewReader(m["risk_score"]))
	d.UseNumber()
	if len(m["risk_score"]) > 0 && d.Decode(&n) == nil {
		if v, err := n.Float64(); err == nil && !math.IsNaN(v) && !math.IsInf(v, 0) {
			score = &v
		}
	}
	return level, score
}

// sanitizeResult bounds stored provider output. It stays untrusted data.
func sanitizeResult(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || !json.Valid(raw) {
		return nil
	}
	if len(raw) > 16<<10 {
		b, _ := json.Marshal(map[string]string{"truncated": "provider result exceeded 16KiB"})
		return b
	}
	return raw
}

// VerifyEvidence independently checks a delivered purchase:
//  1. fetch GET /engine/v1/signal/{signal_hash} and recompute the keccak256
//     signal hash over the returned payload (documented procedure), and
//  2. if a tx hash and RPC URL are available, confirm on chain that the tx
//     succeeded and contains a token Transfer from our wallet to payTo.
//
// Only when both pass is the evidence SETTLED; otherwise UNVERIFIED with a note.
func (c *X402Client) VerifyEvidence(ctx context.Context, ev RiskEvidence) (VerificationStatus, error) {
	if ev.RequestID == "" {
		return VerificationStatus{State: model.EvidenceUnverified, Note: "no signal_hash returned"}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var notes []string
	signalOK, err := c.verifySignal(ctx, ev.RequestID)
	if err != nil {
		notes = append(notes, "signal check: "+err.Error())
	} else {
		notes = append(notes, "signal hash recomputed and matched")
	}
	chainOK := false
	switch {
	case ev.TxHash == nil:
		notes = append(notes, "no tx hash in receipt")
	case c.cfg.RPCURL == "":
		notes = append(notes, "no RPC configured for on-chain check")
	default:
		ok, err := c.verifyTransfer(ctx, *ev.TxHash, ev.Asset, ev.Payer, ev.PayTo)
		if err != nil {
			notes = append(notes, "on-chain check: "+err.Error())
		} else if ok {
			chainOK = true
			notes = append(notes, "on-chain Transfer from payer to payTo confirmed")
		}
	}
	st := model.EvidenceUnverified
	if signalOK && chainOK {
		st = model.EvidenceSettled
	}
	return VerificationStatus{State: st, Note: strings.Join(notes, "; ")}, nil
}

func (c *X402Client) getJSON(ctx context.Context, url string, v any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := c.cfg.HTTP.Do(req)
	if err != nil {
		return errors.New("transport error")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	dec.UseNumber()
	return dec.Decode(v)
}

func (c *X402Client) verifySignal(ctx context.Context, signalHash string) (bool, error) {
	var sig map[string]any
	if err := c.getJSON(ctx, c.cfg.BaseURL+"/engine/v1/signal/"+signalHash, &sig); err != nil {
		return false, err
	}
	payload, ok := sig["payload"].(map[string]any)
	if !ok {
		if s, ok2 := sig["signal"].(map[string]any); ok2 {
			payload, ok = s["payload"].(map[string]any)
		}
	}
	if !ok {
		return false, errors.New("signal response has no payload object")
	}
	got := SignalHash(payload)
	if !strings.EqualFold(strings.TrimPrefix(got, "0x"), strings.TrimPrefix(signalHash, "0x")) {
		return false, errors.New("recomputed signal hash does not match")
	}
	return true, nil
}

// SignalHash implements the documented recipe: keccak256 over compact JSON
// with sorted keys, wallet_address lowercased and <, >, & escaped as <,
// >, & (which is what Go's encoding/json produces for maps).
func SignalHash(payload map[string]any) string {
	cp := make(map[string]any, len(payload))
	for k, v := range payload {
		if k == "wallet_address" {
			if s, ok := v.(string); ok {
				v = strings.ToLower(s)
			}
		}
		cp[k] = v
	}
	b, _ := json.Marshal(cp)
	return "0x" + hex.EncodeToString(keccak(b))
}

var transferTopic = "0x" + hex.EncodeToString(keccak([]byte("Transfer(address,address,uint256)")))

func (c *X402Client) verifyTransfer(ctx context.Context, txHash, asset, from, to string) (bool, error) {
	reqBody, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionReceipt", "params": []string{txHash}})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.RPCURL, bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.cfg.HTTP.Do(req)
	if err != nil {
		return false, errors.New("rpc transport error")
	}
	defer resp.Body.Close()
	var out struct {
		Result *struct {
			Status string `json:"status"`
			Logs   []struct {
				Address string   `json:"address"`
				Topics  []string `json:"topics"`
			} `json:"logs"`
		} `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return false, errors.New("bad rpc response")
	}
	if out.Result == nil {
		return false, errors.New("tx not found / not yet mined")
	}
	if out.Result.Status != "0x1" {
		return false, errors.New("tx reverted")
	}
	topicAddr := func(a string) string {
		return "0x" + strings.Repeat("0", 24) + strings.ToLower(strings.TrimPrefix(a, "0x"))
	}
	for _, l := range out.Result.Logs {
		if !strings.EqualFold(l.Address, asset) || len(l.Topics) < 3 || !strings.EqualFold(l.Topics[0], transferTopic) {
			continue
		}
		if strings.EqualFold(l.Topics[1], topicAddr(from)) && (to == "" || strings.EqualFold(l.Topics[2], topicAddr(to))) {
			return true, nil
		}
	}
	return false, errors.New("no matching token Transfer log in tx")
}

func extraString(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}
