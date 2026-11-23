package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"hash"
)

const (
	TokenExternal  TokenClass = 0
	TokenBootstrap TokenClass = 1
	TokenSession   TokenClass = 2

	tokenDomain  = "tproxy-server-token-v1\x00"
	filterDomain = "tproxy-server-token-filter-v1\x00"
	nonceEntropy = 12
	nonceWidth   = 16
	tokenWidth   = 32
	tokenChars   = 43
)

type TokenClass byte

var tokenEncoding = base64.RawURLEncoding.Strict()

// tokenCodec is immutable. Its filter rejects accidental token candidates in
// public request metadata before performing authentication with the full MAC.
type tokenCodec struct {
	key    [sha256.Size]byte
	filter cipher.Block
}

func newTokenCodec(key [sha256.Size]byte) tokenCodec {
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(filterDomain))
	material := mac.Sum(nil)
	block, err := aes.NewCipher(material[:aes.BlockSize])
	if err != nil {
		panic(err)
	}
	clear(material)
	return tokenCodec{key: key, filter: block}
}

// TokenClassifier is a request-local verifier. Lazily creating its MAC keeps
// ordinary filter misses on the AES-only path and avoids per-candidate allocation.
type TokenClassifier struct {
	codec   *tokenCodec
	mac     hash.Hash
	message [len(tokenDomain) + 1 + nonceWidth]byte
	block   [aes.BlockSize]byte
	digest  [sha256.Size]byte
}

func (codec *tokenCodec) verifier() *TokenClassifier {
	return &TokenClassifier{codec: codec}
}

func (verifier *TokenClassifier) nonceTag(token []byte) uint32 {
	copy(verifier.block[:nonceEntropy], token[:nonceEntropy])
	clear(verifier.block[nonceEntropy:])
	verifier.codec.filter.Encrypt(verifier.block[:], verifier.block[:])
	return binary.BigEndian.Uint32(verifier.block[:4])
}

func (verifier *TokenClassifier) signature(kind TokenClass, nonce []byte) []byte {
	if verifier.mac == nil {
		verifier.mac = hmac.New(sha256.New, verifier.codec.key[:])
		copy(verifier.message[:], tokenDomain)
	} else {
		verifier.mac.Reset()
	}
	verifier.message[len(tokenDomain)] = byte(kind)
	copy(verifier.message[len(tokenDomain)+1:], nonce[:nonceWidth])
	verifier.mac.Write(verifier.message[:])
	return verifier.mac.Sum(verifier.digest[:0])[:nonceWidth]
}

func (verifier *TokenClassifier) signedKind(token []byte) TokenClass {
	if len(token) != tokenWidth {
		return TokenExternal
	}
	bootstrap := hmac.Equal(token[nonceWidth:], verifier.signature(TokenBootstrap, token))
	active := hmac.Equal(token[nonceWidth:], verifier.signature(TokenSession, token))
	if bootstrap {
		return TokenBootstrap
	}
	if active {
		return TokenSession
	}
	return TokenExternal
}

func (verifier *TokenClassifier) Classify(token []byte) TokenClass {
	if len(token) != tokenWidth {
		return TokenExternal
	}
	claimed := binary.BigEndian.Uint32(token[nonceEntropy:nonceWidth])
	if verifier.nonceTag(token) != claimed {
		return TokenExternal
	}
	return verifier.signedKind(token)
}

// Signed accepts older nonces for provenance checks in known carrier fields.
func (verifier *TokenClassifier) Signed(token []byte) bool {
	return verifier.signedKind(token) != TokenExternal
}

func (codec *tokenCodec) issue(kind TokenClass) (string, [sha256.Size]byte, error) {
	var token [tokenWidth]byte
	if _, err := rand.Read(token[:nonceEntropy]); err != nil {
		return "", [sha256.Size]byte{}, err
	}
	verifier := codec.verifier()
	verifier.nonceTag(token[:])
	copy(token[nonceEntropy:nonceWidth], verifier.block[:nonceWidth-nonceEntropy])
	copy(token[nonceWidth:], verifier.signature(kind, token[:]))
	return tokenEncoding.EncodeToString(token[:]), sha256.Sum256(token[:]), nil
}

func (m *Manager) NewTokenClassifier() *TokenClassifier {
	return m.tokens.verifier()
}

func decodeToken(token *[tokenWidth]byte, value string) bool {
	if len(value) != tokenChars {
		return false
	}
	n, err := tokenEncoding.Decode(token[:], []byte(value))
	return err == nil && n == len(token)
}

func tokenHash(value string) ([sha256.Size]byte, error) {
	var token [tokenWidth]byte
	if !decodeToken(&token, value) {
		return [sha256.Size]byte{}, ErrAuthentication
	}
	return sha256.Sum256(token[:]), nil
}
