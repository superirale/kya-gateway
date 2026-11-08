package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/superirale/kya-gateway/internal/canonical"
	"github.com/superirale/kya-gateway/internal/model"
)

// Cross-language vectors consumed by sdk/typescript/test. Regenerate with
// KYA_UPDATE_VECTORS=1 go test ./internal/identity/ (a breaking change!).
type vectors struct {
	SecretKeySeed   string                    `json:"secret_key_seed"`
	PublicKey       string                    `json:"public_key"`
	CanonicalInput  json.RawMessage           `json:"canonical_input"`
	CanonicalOutput string                    `json:"canonical_output"`
	Intent          model.SignedIntentPayload `json:"intent"`
	IntentMessage   string                    `json:"intent_message"`
	IntentSignature string                    `json:"intent_signature"`
	IntentHash      string                    `json:"intent_hash"`
	Cart            json.RawMessage           `json:"cart"`
	CartDigest      string                    `json:"cart_digest"`
}

func buildVectors(t *testing.T) vectors {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	input := json.RawMessage(`{"z":1,"a":[true,null,-5],"s":"line\nquote\"tab\tctl\u0001 é ✓ <&>","n":{"b":"2","a":"1"}}`)
	canon, err := canonical.Canonicalize(input)
	if err != nil {
		t.Fatal(err)
	}
	p := model.SignedIntentPayload{AgentID: "agent_vector_001", MerchantID: "merchant_demo_001", DelegationID: "dlg_vector",
		Intent: model.PurchaseIntent{IntentID: "pi_vector", Action: "purchase", AmountMinor: 35000, Currency: "USD",
			CartDigest: "sha256:" + hex.EncodeToString(make([]byte, 32)), Category: "electronics",
			Timestamp: "2026-11-08T15:00:00Z", Nonce: "AAAAAAAAAAAAAAAAAAAAAA"}}
	msg, _ := IntentMessage(p)
	cart := json.RawMessage(`{"merchant_id":"merchant_demo_001","items":[{"sku":"sku_headphones_nc","quantity":1,"unit_price_minor":35000}],"currency":"USD","total_minor":35000}`)
	cc, _ := canonical.Canonicalize(cart)
	sum := sha256.Sum256(cc)
	return vectors{
		SecretKeySeed: EncodeB64URL(seed), PublicKey: EncodeB64URL(priv.Public().(ed25519.PublicKey)),
		CanonicalInput: input, CanonicalOutput: string(canon), Intent: p, IntentMessage: string(msg),
		IntentSignature: EncodeB64URL(ed25519.Sign(priv, msg)), IntentHash: HashMessage(msg),
		Cart: cart, CartDigest: "sha256:" + hex.EncodeToString(sum[:]),
	}
}

func TestCrossLanguageVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "signing-vectors.json")
	got := buildVectors(t)
	if os.Getenv("KYA_UPDATE_VECTORS") == "1" {
		b, _ := json.MarshalIndent(got, "", "  ")
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing vectors (run with KYA_UPDATE_VECTORS=1): %v", err)
	}
	var want vectors
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if want.CanonicalOutput != got.CanonicalOutput || want.IntentSignature != got.IntentSignature ||
		want.CartDigest != got.CartDigest || !reflect.DeepEqual(want.Intent, got.Intent) {
		t.Fatal("signing vectors changed: canonicalization or signing is no longer backward compatible")
	}
}
