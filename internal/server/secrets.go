package server

import (
	"encoding/binary"
	"net/http"
	"strings"

	"github.com/love4taylor/caddy-tproxy/internal/config"
	"github.com/love4taylor/caddy-tproxy/internal/session"
)

const credentialTextLength = 43

func (s *Server) bridgeProfile(r *http.Request) *config.Profile {
	if r.Method != http.MethodGet || r.URL.EscapedPath() != s.base {
		return nil
	}
	value, found := strings.CutPrefix(r.URL.RawQuery, "bridge=")
	if !found || len(value) != credentialTextLength {
		return nil
	}
	var raw [32]byte
	if n, err := strictToken.Decode(raw[:], []byte(value)); err == nil && n == len(raw) {
		return s.manager.MatchCapability(raw[:])
	}
	return nil
}

func (s *Server) hasInternalSecret(r *http.Request) bool {
	if s.bridgeProfile(r) != nil {
		return true
	}
	guard := metadataGuard{manager: s.manager}
	for _, value := range r.Header.Values("Authorization") {
		if token, ok := bearerToken(value); ok && guard.signedCarrierToken(token) {
			return true
		}
	}
	for _, value := range r.Header["Sec-Websocket-Protocol"] {
		for entry := range strings.SplitSeq(value, ",") {
			token, _, _, ok := webSocketCredentials(strings.TrimSpace(entry))
			if ok && tokenSyntax(token) && guard.signedCarrierToken(token) {
				return true
			}
		}
	}
	// Unclaimed bodies must reach the next Caddy handler without being read.
	// Check the actual wire target as well as the current path and query,
	// since Caddy handlers above the module may have rewritten the latter.
	path := r.URL.EscapedPath()
	if guard.has(r.URL.RawQuery) || guard.has(path) || guard.has(r.URL.Host) || guard.has(r.Host) {
		return true
	}
	sentPath, sentQuery, _ := strings.Cut(r.RequestURI, "?")
	if (sentPath != path || sentQuery != r.URL.RawQuery) && guard.has(r.RequestURI) {
		return true
	}
	for name, values := range r.Header {
		if guard.has(name) {
			return true
		}
		for _, value := range values {
			if guard.has(value) {
				return true
			}
		}
	}
	return false
}

// A keyed filter gates full HMAC verification at every token-sized window.
// The verifier is reused for all metadata fields in a single request.
type metadataGuard struct {
	manager *session.Manager
	checker *session.TokenClassifier
}

func (guard *metadataGuard) verifier() *session.TokenClassifier {
	if guard.checker == nil {
		guard.checker = guard.manager.NewTokenClassifier()
	}
	return guard.checker
}

func (guard *metadataGuard) signedCarrierToken(token string) bool {
	var raw [32]byte
	n, err := strictToken.Decode(raw[:], []byte(token))
	return err == nil && n == len(raw) && guard.verifier().Signed(raw[:])
}

func (guard *metadataGuard) has(field string) bool {
	if len(field) < credentialTextLength {
		return false
	}
	if strings.IndexByte(field, '%') < 0 {
		start := firstCredentialRun(field)
		if start < 0 {
			return false
		}
		field = field[start:]
	}
	var high, upper, lower, low uint64
	var candidate [32]byte
	run := 0
	var tail uint64
	for i := 0; i < len(field); i++ {
		c := field[i]
		if c == '%' && i+2 < len(field) {
			hi, lo := hexNibble(field[i+1]), hexNibble(field[i+2])
			if hi < 16 && lo < 16 {
				c = hi<<4 | lo
				i += 2
			}
		}
		sextet := credentialSextets[c]
		if sextet == 0 {
			run = 0
			continue
		}
		// Each window has 256 payload bits and two final padding bits.
		// Carry those two bits into the register on the next sextet.
		value := uint64(sextet - 1)
		high, upper, lower, low = high<<6|upper>>58, upper<<6|lower>>58, lower<<6|low>>58, low<<6|tail<<4|value>>2
		tail = value & 3
		if run < credentialTextLength-1 {
			run++
			continue
		}
		binary.BigEndian.PutUint64(candidate[:8], high)
		binary.BigEndian.PutUint64(candidate[8:16], upper)
		binary.BigEndian.PutUint64(candidate[16:24], lower)
		binary.BigEndian.PutUint64(candidate[24:], low)
		if guard.manager.ContainsCapability(candidate[:]) || guard.verifier().Classify(candidate[:]) != session.TokenExternal {
			return true
		}
	}
	return false
}

// In plain metadata, a separator invalidates all windows that cross it.
// Start at the far end of each possible window to skip short runs in bulk.
func firstCredentialRun(field string) int {
	for start := 0; start <= len(field)-credentialTextLength; {
		end := start + credentialTextLength - 1
		for end >= start && credentialSextets[field[end]] != 0 {
			end--
		}
		if end < start {
			return start
		}
		start = end + 1
	}
	return -1
}

var credentialSextets = func() (table [256]byte) {
	const digits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for i := range len(digits) {
		table[digits[i]] = byte(i + 1)
	}
	return
}()

func hexNibble(c byte) byte {
	if '0' <= c && c <= '9' {
		return c - '0'
	}
	c |= 32
	if 'a' <= c && c <= 'f' {
		return c - 'a' + 10
	}
	return 255
}
