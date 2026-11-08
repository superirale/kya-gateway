// Package identity implements Ed25519 agent key handling: proof-of-possession
// challenges, key rotation and purchase-intent signature verification.
//
// Trust boundary: a valid signature proves control of a registered key. It
// does not prove the real-world identity of the agent's operator or consumer.
package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"

	"github.com/superirale/kya-gateway/internal/canonical"
	"github.com/superirale/kya-gateway/internal/model"
)

var (
	ErrBadPublicKey = errors.New("identity: public key must be 32 bytes base64url")
	ErrBadSignature = errors.New("identity: signature must be 64 bytes base64url")
	ErrSigInvalid   = errors.New("identity: signature verification failed")
	agentIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_\-]{2,63}$`)
)

func ValidAgentID(id string) bool { return agentIDPattern.MatchString(id) }

// DecodeB64URL accepts unpadded or padded base64url.
func DecodeB64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func EncodeB64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := DecodeB64URL(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, ErrBadPublicKey
	}
	return ed25519.PublicKey(b), nil
}

func ParseSignature(s string) ([]byte, error) {
	b, err := DecodeB64URL(s)
	if err != nil || len(b) != ed25519.SignatureSize {
		return nil, ErrBadSignature
	}
	return b, nil
}

// ChallengePayload is signed (under DomainAgentChallenge) to prove possession
// of the key being registered. Binding the public key prevents substitution.
type ChallengePayload struct {
	AgentID     string `json:"agent_id"`
	ChallengeID string `json:"challenge_id"`
	Challenge   string `json:"challenge"`
	PublicKey   string `json:"public_key"`
}

func ChallengeMessage(ch model.Challenge, publicKeyB64 string) ([]byte, error) {
	return canonical.SigningMessage(canonical.DomainAgentChallenge, ChallengePayload{
		AgentID: ch.AgentID, ChallengeID: ch.ChallengeID, Challenge: ch.Challenge, PublicKey: publicKeyB64,
	})
}

// RotatePayload is signed by BOTH the current key and the new key.
type RotatePayload struct {
	AgentID       string `json:"agent_id"`
	ChallengeID   string `json:"challenge_id"`
	Challenge     string `json:"challenge"`
	OldKeyVersion int    `json:"old_key_version"`
	NewPublicKey  string `json:"new_public_key"`
}

func RotateMessage(ch model.Challenge, oldVersion int, newKeyB64 string) ([]byte, error) {
	return canonical.SigningMessage(canonical.DomainAgentRotate, RotatePayload{
		AgentID: ch.AgentID, ChallengeID: ch.ChallengeID, Challenge: ch.Challenge,
		OldKeyVersion: oldVersion, NewPublicKey: newKeyB64,
	})
}

func IntentMessage(p model.SignedIntentPayload) ([]byte, error) {
	return canonical.SigningMessage(canonical.DomainPurchaseIntent, p)
}

// HashMessage returns "sha256:<hex>" of a signing message.
func HashMessage(msg []byte) string {
	sum := sha256.Sum256(msg)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func Verify(pub ed25519.PublicKey, msg, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return ErrSigInvalid
	}
	if !ed25519.Verify(pub, msg, sig) {
		return ErrSigInvalid
	}
	return nil
}

// Fingerprint gives a short, non-secret identifier for a public key.
func Fingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}
