package telegraph

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// Minimal EVM helpers: keccak256, addresses and EIP-712 signing of the
// EIP-3009 TransferWithAuthorization message used by x402 "exact" payments.

func keccak(parts ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// Wallet is an EVM key. The private key never leaves this struct and is never
// logged or serialized.
type Wallet struct {
	priv    *secp256k1.PrivateKey
	address string
}

func (w *Wallet) String() string { return "Wallet(" + w.address + ")" } // never print key

func ParseWallet(hexKey string) (*Wallet, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(hexKey), "0x"))
	if err != nil || len(b) != 32 {
		return nil, errors.New("telegraph: wallet key must be 32-byte hex")
	}
	priv := secp256k1.PrivKeyFromBytes(b)
	for i := range b {
		b[i] = 0
	}
	return &Wallet{priv: priv, address: pubToAddress(priv.PubKey())}, nil
}

func pubToAddress(pub *secp256k1.PublicKey) string {
	unc := pub.SerializeUncompressed()
	return checksumAddress(keccak(unc[1:])[12:])
}

func (w *Wallet) Address() string { return w.address }

// checksumAddress implements EIP-55.
func checksumAddress(addr []byte) string {
	h := hex.EncodeToString(addr)
	hash := hex.EncodeToString(keccak([]byte(h)))
	out := []byte(h)
	for i := range out {
		if out[i] >= 'a' && hash[i] >= '8' {
			out[i] -= 32
		}
	}
	return "0x" + string(out)
}

// SignHash returns a 65-byte Ethereum signature r||s||v with v in {27,28}.
func (w *Wallet) SignHash(hash []byte) []byte {
	compact := ecdsa.SignCompact(w.priv, hash, false) // [v, r(32), s(32)], v = 27 + recid
	sig := make([]byte, 65)
	copy(sig, compact[1:])
	sig[64] = compact[0]
	return sig
}

// RecoverAddress recovers the signer of an r||s||v signature.
func RecoverAddress(hash, sig []byte) (string, error) {
	if len(sig) != 65 {
		return "", errors.New("bad signature length")
	}
	compact := make([]byte, 65)
	compact[0] = sig[64]
	copy(compact[1:], sig[:64])
	pub, _, err := ecdsa.RecoverCompact(compact, hash)
	if err != nil {
		return "", err
	}
	return pubToAddress(pub), nil
}

func parseAddress(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != 20 {
		return nil, fmt.Errorf("invalid address %q", s)
	}
	return b, nil
}

func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func uint256(n *big.Int) []byte { return pad32(n.Bytes()) }

var (
	domainTypeHash   = keccak([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"))
	transferTypeHash = keccak([]byte("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"))
)

// TransferAuthorization is the EIP-3009 message. Numeric fields are decimal strings.
type TransferAuthorization struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Value       string `json:"value"`
	ValidAfter  string `json:"validAfter"`
	ValidBefore string `json:"validBefore"`
	Nonce       string `json:"nonce"` // 0x-prefixed 32-byte hex
}

type EIP712Domain struct {
	Name              string
	Version           string
	ChainID           *big.Int
	VerifyingContract string
}

func (d EIP712Domain) separator() ([]byte, error) {
	vc, err := parseAddress(d.VerifyingContract)
	if err != nil {
		return nil, err
	}
	return keccak(domainTypeHash, keccak([]byte(d.Name)), keccak([]byte(d.Version)), uint256(d.ChainID), pad32(vc)), nil
}

func dec(s string) (*big.Int, error) {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || n.Sign() < 0 || n.BitLen() > 256 {
		return nil, fmt.Errorf("invalid uint256 %q", s)
	}
	return n, nil
}

// TransferDigest computes the EIP-712 digest to sign.
func TransferDigest(d EIP712Domain, a TransferAuthorization) ([]byte, error) {
	sep, err := d.separator()
	if err != nil {
		return nil, err
	}
	from, err := parseAddress(a.From)
	if err != nil {
		return nil, err
	}
	to, err := parseAddress(a.To)
	if err != nil {
		return nil, err
	}
	var nums [3]*big.Int
	for i, s := range []string{a.Value, a.ValidAfter, a.ValidBefore} {
		if nums[i], err = dec(s); err != nil {
			return nil, err
		}
	}
	nonce, err := hex.DecodeString(strings.TrimPrefix(a.Nonce, "0x"))
	if err != nil || len(nonce) != 32 {
		return nil, errors.New("nonce must be 32 bytes")
	}
	structHash := keccak(transferTypeHash, pad32(from), pad32(to), uint256(nums[0]), uint256(nums[1]), uint256(nums[2]), nonce)
	return keccak([]byte{0x19, 0x01}, sep, structHash), nil
}

func randomNonce32() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "0x" + hex.EncodeToString(b)
}
