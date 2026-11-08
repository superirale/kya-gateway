// Package canonical implements the deterministic JSON encoding used for every
// signed KYA payload (agent challenges, delegations and purchase intents).
//
// The encoding is a strict subset of RFC 8785 (JCS):
//   - object keys sorted by UTF-16 code units (identical to byte order for the
//     ASCII keys KYA uses),
//   - no insignificant whitespace,
//   - strings escaped minimally (only '"', '\\' and control characters),
//   - numbers must be integers within the IEEE-754 safe range (|n| <= 2^53-1);
//     floats are rejected so signers in different languages cannot disagree.
//
// Duplicate object keys are rejected when parsing raw input, closing the
// "which duplicate wins" canonicalization ambiguity.
package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxSafeInteger is the largest integer exactly representable in a JS number.
const MaxSafeInteger = 1<<53 - 1

var (
	ErrDuplicateKey = errors.New("canonical: duplicate object key")
	ErrFloat        = errors.New("canonical: non-integer numbers are not allowed")
	ErrUnsafeInt    = errors.New("canonical: integer outside safe range")
	ErrInvalidUTF8  = errors.New("canonical: invalid UTF-8 in string")
)

// Marshal encodes v (any value encodable by encoding/json) canonically.
func Marshal(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Canonicalize(raw)
}

// Canonicalize re-encodes raw JSON canonically, rejecting duplicate keys,
// floats and unsafe integers.
func Canonicalize(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	val, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("canonical: trailing data after JSON value")
	}
	var buf bytes.Buffer
	if err := encode(&buf, val); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CheckNoDuplicateKeys validates that raw JSON contains no duplicate keys at
// any depth. It is used on inbound request bodies before struct decoding.
func CheckNoDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	_, err := decodeValue(dec)
	return err
}

type object struct {
	keys []string
	vals map[string]any
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := object{vals: map[string]any{}}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := kt.(string)
				if !ok {
					return nil, errors.New("canonical: object key is not a string")
				}
				if _, dup := obj.vals[key]; dup {
					return nil, fmt.Errorf("%w: %q", ErrDuplicateKey, key)
				}
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				obj.keys = append(obj.keys, key)
				obj.vals[key] = v
			}
			if _, err := dec.Token(); err != nil { // '}'
				return nil, err
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			if _, err := dec.Token(); err != nil { // ']'
				return nil, err
			}
			return arr, nil
		}
		return nil, fmt.Errorf("canonical: unexpected delimiter %v", t)
	default:
		return tok, nil
	}
}

func encode(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		s := t.String()
		if strings.ContainsAny(s, ".eE") {
			return ErrFloat
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n > MaxSafeInteger || n < -MaxSafeInteger {
			return ErrUnsafeInt
		}
		buf.WriteString(strconv.FormatInt(n, 10)) // normalizes "-0" and leading zeros
	case string:
		return encodeString(buf, t)
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encode(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case object:
		keys := append([]string(nil), t.keys...)
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := encode(buf, t.vals[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonical: unsupported type %T", v)
	}
	return nil
}

func encodeString(buf *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return ErrInvalidUTF8
	}
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
	return nil
}

// SigningMessage builds the domain-separated byte string that is signed:
// "<domain>\n" + canonical(payload). Domain separation prevents a signature
// produced for one message type being replayed as another.
func SigningMessage(domain string, payload any) ([]byte, error) {
	c, err := Marshal(payload)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(domain)+1+len(c))
	out = append(out, domain...)
	out = append(out, '\n')
	out = append(out, c...)
	return out, nil
}

// Signing domains. Changing one is a breaking protocol change.
const (
	DomainAgentChallenge = "KYA-AGENT-CHALLENGE-V1"
	DomainAgentRotate    = "KYA-AGENT-ROTATE-V1"
	DomainDelegation     = "KYA-DELEGATION-V1"
	DomainPurchaseIntent = "KYA-PURCHASE-INTENT-V1"
)
