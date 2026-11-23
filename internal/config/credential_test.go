package config

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCapabilityBindsHostAndPrefix(t *testing.T) {
	const host = "relay.example.net"
	key := []byte("0123456789abcdef")
	for _, p := range []struct{ prefix, input string }{
		{"", "tdesktop-web-proxy-bridge-v1\n" + host},
		{"a/b", "tdesktop-web-proxy-bridge-v2\n" + host + "\na/b"},
	} {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(p.input))
		want := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
		if got := CapabilityString(DeriveCapability(host, p.prefix, key)); got != want {
			t.Fatalf("wrong capability for prefix %q", p.prefix)
		}
	}
	for _, prefix := range []string{"safe/a-B_2", "", "0"} {
		if err := ValidateBasePath(prefix); err != nil {
			t.Errorf("valid prefix %q: %v", prefix, err)
		}
	}
	for _, prefix := range []string{"/a", "a/%20", "a//b", "a/.", "a/_b", "a\\b", "a/"} {
		if ValidateBasePath(prefix) == nil {
			t.Errorf("accepted ambiguous prefix %q", prefix)
		}
	}
}

func TestReadClientSecretFile(t *testing.T) {
	dir := t.TempDir()
	key := [17]byte{0xdd, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	const hexKey = "dd0102030405060708090a0b0c0d0e0f10"

	for _, test := range []struct {
		name, text string
		mode       os.FileMode
		valid      bool
	}{
		{"hex", hexKey + "\n", 0o600, true},
		{"base64url", base64.RawURLEncoding.EncodeToString(key[:]), 0o600, true},
		{"padded-base64url", base64.URLEncoding.EncodeToString(key[:]), 0o400, true},
		{"limit", hexKey + strings.Repeat(" ", 256-len(hexKey)), 0o600, true},
		{"over-limit", hexKey + strings.Repeat(" ", 257-len(hexKey)), 0o600, false},
		{"shared", hexKey, 0o640, false},
		{"empty", "", 0o600, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(dir, test.name)
			if err := os.WriteFile(path, []byte(test.text), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, test.mode); err != nil {
				t.Fatal(err)
			}
			decoded, err := ReadClientSecret(path)
			if !test.valid {
				if err == nil {
					t.Fatal("accepted invalid credential file")
				}
				return
			}
			if err != nil || !bytes.Equal(decoded, key[:]) {
				t.Fatalf("valid credential file returned %d bytes, error %v", len(decoded), err)
			}
		})
	}
}

func TestSigningKeyRejectsUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	for _, test := range []struct {
		name   string
		length int
		mode   os.FileMode
		valid  bool
	}{
		{"short", 31, 0o600, false}, {"long", 33, 0o600, false}, {"shared", 32, 0o644, false}, {"private", 32, 0o600, true},
	} {
		p := filepath.Join(dir, test.name)
		data := make([]byte, test.length)
		data[0] = 0x23
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		// Apply the test mode explicitly so a restrictive umask cannot turn
		// the shared file into an owner-only file before validation.
		if err := os.Chmod(p, test.mode); err != nil {
			t.Fatal(err)
		}
		key, err := ReadTokenKey(p)
		if test.valid != (err == nil) || (err == nil && key != ([32]byte{0x23})) {
			t.Errorf("key %s returned %v", test.name, err)
		}
	}
	for _, p := range []string{dir, filepath.Join(dir, "never-created")} {
		if _, err := ReadTokenKey(p); err == nil {
			t.Errorf("accepted non-regular credential input %q", p)
		}
	}
}
