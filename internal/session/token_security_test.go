package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestWireTokenAuthentication(t *testing.T) {
	key := [32]byte{9, 5, 0, 1}
	signer := newTokenCodec(key)
	restart := newTokenCodec(key)
	other := newTokenCodec([32]byte{77})
	for _, kind := range []TokenClass{TokenBootstrap, TokenSession} {
		value, hash, err := signer.issue(kind)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(raw) != 32 || sha256.Sum256(raw) != hash {
			t.Fatal("invalid token encoding")
		}
		h := hmac.New(sha256.New, key[:])
		h.Write(append([]byte("tproxy-server-token-v1\x00"), byte(kind)))
		h.Write(raw[:16])
		if !hmac.Equal(h.Sum(nil)[:16], raw[16:]) {
			t.Fatal("incompatible token signature")
		}
		if restart.verifier().Classify(raw) != kind || other.verifier().Classify(raw) != TokenExternal {
			t.Fatal("token provenance did not survive restart or crossed keys")
		}
		verifier := signer.verifier()
		for i := range raw {
			raw[i] ^= 0x04
			if verifier.Classify(raw) != TokenExternal {
				t.Fatalf("accepted changed byte %d", i)
			}
			raw[i] ^= 0x04
		}
	}
}
