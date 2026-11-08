// Package auth handles merchant API keys, the admin key and demo consumer
// sessions. Demo consumer auth is a local test account, NOT identity proofing.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

func hashKey(k string) [32]byte { return sha256.Sum256([]byte(k)) }

// MerchantKeys maps API-key hashes to merchant IDs (keys are not kept in clear).
type MerchantKeys struct{ byHash map[[32]byte]string }

// ParseMerchantKeys parses "merchant_id:api_key,merchant_id2:api_key2".
func ParseMerchantKeys(spec string) (*MerchantKeys, error) {
	m := &MerchantKeys{byHash: map[[32]byte]string{}}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, key, ok := strings.Cut(part, ":")
		if !ok || id == "" || len(key) < 16 {
			return nil, errors.New("merchant keys must be merchant_id:key with key >= 16 chars")
		}
		m.byHash[hashKey(key)] = id
	}
	return m, nil
}

// Lookup returns the merchant for a bearer key (constant-time per candidate).
func (m *MerchantKeys) Lookup(key string) (string, bool) {
	if key == "" {
		return "", false
	}
	h := hashKey(key)
	found := ""
	for kh, id := range m.byHash {
		if subtle.ConstantTimeCompare(kh[:], h[:]) == 1 {
			found = id
		}
	}
	return found, found != ""
}

func EqualSecret(a, b string) bool {
	ha, hb := hashKey(a), hashKey(b)
	return b != "" && subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

// Consumers is the seeded set of demo consumer accounts.
type Consumers struct{ pw map[string][32]byte }

// ParseConsumers parses "alice:password,bob:password".
func ParseConsumers(spec string) *Consumers {
	c := &Consumers{pw: map[string][32]byte{}}
	for _, part := range strings.Split(spec, ",") {
		if u, p, ok := strings.Cut(strings.TrimSpace(part), ":"); ok && u != "" && p != "" {
			c.pw[u] = hashKey(p)
		}
	}
	return c
}

func (c *Consumers) Check(user, pass string) bool {
	want, ok := c.pw[user]
	got := hashKey(pass)
	return ok && subtle.ConstantTimeCompare(want[:], got[:]) == 1
}

// Sessions issues stateless HMAC-signed consumer session tokens.
type Sessions struct {
	secret []byte
	TTL    time.Duration
}

func NewSessions(secret []byte, ttl time.Duration) *Sessions {
	return &Sessions{secret: secret, TTL: ttl}
}

func (s *Sessions) mac(body string) string {
	h := hmac.New(sha256.New, s.secret)
	h.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func (s *Sessions) Issue(user string, now time.Time) (string, time.Time) {
	exp := now.Add(s.TTL).UTC().Truncate(time.Second)
	body := base64.RawURLEncoding.EncodeToString([]byte(user)) + "." + strconv.FormatInt(exp.Unix(), 10)
	return "cs_" + body + "." + s.mac(body), exp
}

func (s *Sessions) Verify(tok string, now time.Time) (string, error) {
	tok, ok := strings.CutPrefix(tok, "cs_")
	if !ok {
		return "", errors.New("bad token")
	}
	i := strings.LastIndexByte(tok, '.')
	if i < 0 {
		return "", errors.New("bad token")
	}
	body, sig := tok[:i], tok[i+1:]
	if !hmac.Equal([]byte(sig), []byte(s.mac(body))) {
		return "", errors.New("bad token signature")
	}
	u64, expS, ok := strings.Cut(body, ".")
	if !ok {
		return "", errors.New("bad token")
	}
	exp, err := strconv.ParseInt(expS, 10, 64)
	if err != nil || now.Unix() >= exp {
		return "", errors.New("session expired")
	}
	u, err := base64.RawURLEncoding.DecodeString(u64)
	if err != nil {
		return "", errors.New("bad token")
	}
	return string(u), nil
}

// ConsumerRef derives the pseudonymous consumer reference stored in claims.
func (s *Sessions) ConsumerRef(user string) string {
	h := hmac.New(sha256.New, s.secret)
	h.Write([]byte("consumer-ref:" + user))
	return "cr_" + hex.EncodeToString(h.Sum(nil)[:10])
}
