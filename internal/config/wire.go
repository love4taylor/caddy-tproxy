package config

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

const MaxBasePathLength = 128

// The loopback WebView carrier can deliver a message of at most 2 MiB.
const MaxCarrierBatchBytes = 2 << 20

func ValidateHostname(host string) error {
	dot := strings.LastIndexByte(host, '.')
	if len(host) > 253 || dot < 0 {
		return errors.New("expected a fully qualified lowercase ASCII hostname")
	}
	digits := host[dot+1:]
	allowed := "0123456789"
	if strings.HasPrefix(digits, "0x") {
		digits = digits[2:]
		allowed += "abcdef"
	}
	if strings.Trim(digits, allowed) == "" {
		return errors.New("numeric hostname suffix can be interpreted as an IP address")
	}
	width := 0
	for i := range len(host) {
		c := host[i]
		if c == '.' {
			if width == 0 || host[i-1] == '-' {
				return errors.New("empty hostname label or trailing hyphen")
			}
			width = 0
			continue
		}
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' && width > 0) {
			return errors.New("invalid character in hostname label")
		}
		width++
		if width > 63 {
			return errors.New("hostname label exceeds 63 bytes")
		}
	}
	if width == 0 || host[len(host)-1] == '-' {
		return errors.New("empty hostname label or trailing hyphen")
	}
	return nil
}

func ValidateBasePath(path string) error {
	if path == "" {
		return nil
	}
	if len(path) > MaxBasePathLength {
		return errors.New("WEB relay prefix exceeds 128 bytes")
	}
	first := true
	for i := range len(path) {
		c := path[i]
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' {
			first = false
			continue
		}
		if first || (c != '/' && c != '-' && c != '_') {
			return errors.New("invalid WEB relay prefix segment")
		}
		first = c == '/'
	}
	if first {
		return errors.New("WEB relay prefix ends with an empty segment")
	}
	return nil
}

func Base(prefix string) string {
	if prefix != "" {
		return "/" + prefix + "/"
	}
	return "/"
}

func (c Config) Base() string { return Base(c.BasePath) }

func DeriveCapability(host, prefix string, key []byte) (out [sha256.Size]byte) {
	const rootLabel = "tdesktop-web-proxy-bridge-v1\n"
	const prefixLabel = "tdesktop-web-proxy-bridge-v2\n"
	input := rootLabel + host
	if prefix != "" {
		input = prefixLabel + host + "\n" + prefix
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(input))
	mac.Sum(out[:0])
	return out
}

func CapabilityString(capability [sha256.Size]byte) string {
	return base64.RawURLEncoding.EncodeToString(capability[:])
}

func DecodeSecret(text []byte) ([]byte, error) {
	text = bytes.TrimSpace(text)
	var key []byte
	var n int
	var err error
	switch len(text) {
	case 32, 34:
		key = make([]byte, hex.DecodedLen(len(text)))
		n, err = hex.Decode(key, text)
	default:
		encoding := base64.RawURLEncoding
		if bytes.IndexByte(text, '=') >= 0 {
			encoding = base64.URLEncoding
		}
		key = make([]byte, encoding.DecodedLen(len(text)))
		n, err = encoding.Decode(key, text)
	}
	if err == nil && (n == 16 || (n == 17 && key[0] == 0xdd)) {
		return key[:n], nil
	}
	clear(key)
	return nil, errors.New("expected a 16-byte MTProxy secret with an optional dd prefix")
}
