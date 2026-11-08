package telegraph

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Minimal JSON-RPC + legacy (EIP-155) transaction support, used only by the
// telegraph-probe tool to mint test USDC on Sepolia. KYA itself never sends
// transactions: Telegraph payments are gasless EIP-3009 authorizations.

type RPC struct {
	URL  string
	HTTP *http.Client
}

func (r RPC) call(ctx context.Context, method string, params any, out any) error {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, r.URL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	hc := r.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("rpc %s: transport error", method)
	}
	defer resp.Body.Close()
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&env); err != nil {
		return fmt.Errorf("rpc %s: bad response", method)
	}
	if env.Error != nil {
		return fmt.Errorf("rpc %s: %s", method, env.Error.Message)
	}
	return json.Unmarshal(env.Result, out)
}

func hexBig(s string) (*big.Int, error) {
	n, ok := new(big.Int).SetString(strings.TrimPrefix(s, "0x"), 16)
	if !ok {
		return nil, fmt.Errorf("bad hex quantity %q", s)
	}
	return n, nil
}

func (r RPC) quantity(ctx context.Context, method string, params ...any) (*big.Int, error) {
	if params == nil {
		params = []any{}
	}
	var s string
	if err := r.call(ctx, method, params, &s); err != nil {
		return nil, err
	}
	return hexBig(s)
}

// TokenBalance returns balanceOf(owner) for an ERC-20 token.
func (r RPC) TokenBalance(ctx context.Context, token, owner string) (*big.Int, error) {
	o, err := parseAddress(owner)
	if err != nil {
		return nil, err
	}
	data := "0x70a08231" + hex.EncodeToString(pad32(o))
	var s string
	if err := r.call(ctx, "eth_call", []any{map[string]string{"to": token, "data": data}, "latest"}, &s); err != nil {
		return nil, err
	}
	return hexBig(s)
}

func (r RPC) ETHBalance(ctx context.Context, addr string) (*big.Int, error) {
	return r.quantity(ctx, "eth_getBalance", addr, "latest")
}

// rlp encodes byte strings and lists (enough for legacy transactions).
func rlpBytes(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return b
	}
	return append(rlpHeader(0x80, len(b)), b...)
}

func rlpList(items ...[]byte) []byte {
	var payload []byte
	for _, it := range items {
		payload = append(payload, it...)
	}
	return append(rlpHeader(0xc0, len(payload)), payload...)
}

func rlpHeader(base byte, n int) []byte {
	if n < 56 {
		return []byte{base + byte(n)}
	}
	l := new(big.Int).SetInt64(int64(n)).Bytes()
	return append([]byte{base + 55 + byte(len(l))}, l...)
}

func rlpInt(n *big.Int) []byte { return rlpBytes(n.Bytes()) } // zero encodes as empty string

// SendContractCall signs and broadcasts a legacy EIP-155 tx calling `to` with
// `data`, then waits for the receipt. Returns the tx hash.
func (r RPC) SendContractCall(ctx context.Context, w *Wallet, to string, data []byte) (string, error) {
	toB, err := parseAddress(to)
	if err != nil {
		return "", err
	}
	chainID, err := r.quantity(ctx, "eth_chainId")
	if err != nil {
		return "", err
	}
	nonce, err := r.quantity(ctx, "eth_getTransactionCount", w.Address(), "pending")
	if err != nil {
		return "", err
	}
	gasPrice, err := r.quantity(ctx, "eth_gasPrice")
	if err != nil {
		return "", err
	}
	gasPrice.Mul(gasPrice, big.NewInt(12)).Div(gasPrice, big.NewInt(10)) // +20% headroom
	dataHex := "0x" + hex.EncodeToString(data)
	gas, err := r.quantity(ctx, "eth_estimateGas", map[string]string{"from": w.Address(), "to": to, "data": dataHex})
	if err != nil {
		return "", err
	}
	gas.Mul(gas, big.NewInt(13)).Div(gas, big.NewInt(10)) // +30% headroom
	raw := SignLegacyTx(w, nonce, gasPrice, gas, toB, new(big.Int), data, chainID)
	var txHash string
	if err := r.call(ctx, "eth_sendRawTransaction", []any{"0x" + hex.EncodeToString(raw)}, &txHash); err != nil {
		return "", err
	}
	for {
		var rc *struct {
			Status string `json:"status"`
		}
		if err := r.call(ctx, "eth_getTransactionReceipt", []any{txHash}, &rc); err == nil && rc != nil {
			if rc.Status != "0x1" {
				return txHash, errors.New("transaction reverted")
			}
			return txHash, nil
		}
		select {
		case <-ctx.Done():
			return txHash, errors.New("timed out waiting for receipt (tx may still confirm)")
		case <-time.After(3 * time.Second):
		}
	}
}

// SignLegacyTx returns the RLP-encoded, EIP-155-signed legacy transaction.
func SignLegacyTx(w *Wallet, nonce, gasPrice, gas *big.Int, to []byte, value *big.Int, data []byte, chainID *big.Int) []byte {
	zero := new(big.Int)
	unsigned := rlpList(rlpInt(nonce), rlpInt(gasPrice), rlpInt(gas), rlpBytes(to), rlpInt(value), rlpBytes(data),
		rlpInt(chainID), rlpInt(zero), rlpInt(zero))
	sig := w.SignHash(keccak(unsigned)) // r||s||v, v in {27,28}
	v := new(big.Int).Add(new(big.Int).Mul(chainID, big.NewInt(2)), big.NewInt(int64(sig[64]-27)+35))
	return rlpList(rlpInt(nonce), rlpInt(gasPrice), rlpInt(gas), rlpBytes(to), rlpInt(value), rlpBytes(data),
		rlpInt(v), rlpBytes(trimZeros(sig[:32])), rlpBytes(trimZeros(sig[32:64])))
}

func trimZeros(b []byte) []byte {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

// MintCalldata encodes mint(address,uint256).
func MintCalldata(to string, amount *big.Int) ([]byte, error) {
	a, err := parseAddress(to)
	if err != nil {
		return nil, err
	}
	data, _ := hex.DecodeString("40c10f19")
	data = append(data, pad32(a)...)
	return append(data, uint256(amount)...), nil
}
