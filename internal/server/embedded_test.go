package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/love4taylor/caddy-tproxy/internal/config"
	"github.com/love4taylor/caddy-tproxy/internal/frame"
)

func TestEmbeddedRejectsSettingsWithNoDownlinkBudget(t *testing.T) {
	for _, tt := range []struct {
		name  string
		apply func(*config.Config)
		want  string
	}{
		{"profile overrides", func(c *config.Config) {
			c.Profiles[0].Limits.MaxPendingPerSession = 1 << 20
		}, "profile \"embedded\": max_pending_per_session"},
		{"inherited items", func(c *config.Config) {
			c.Limits.MaxPendingItemsPerSession = 4096
		}, "profile \"embedded\": max_pending_items_per_session"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Profiles = []config.Profile{{Name: "embedded"}}
			tt.apply(&cfg)
			s, err := NewEmbedded(cfg, [32]byte{1}, func(*http.Request) (string, error) { return "192.0.2.4", nil })
			if err == nil {
				s.Shutdown()
				t.Fatal("accepted a relay that could never send DATA")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("got %v, want %q", err, tt.want)
			}
		})
	}
}

type readDeadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (w *readDeadlineRecorder) SetReadDeadline(t time.Time) error {
	w.deadline = t
	return nil
}

func TestEmbeddedPreservesListenerReadTimeout(t *testing.T) {
	s, _ := embeddedFixture(t)
	req := httptest.NewRequest(http.MethodPost, "https://proxy.example.test"+s.base+"invalid", strings.NewReader("body"))
	for _, timeout := range []time.Duration{0, time.Second} {
		ctx := context.WithValue(req.Context(), http.ServerContextKey, &http.Server{ReadTimeout: timeout})
		w := &readDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
		s.ServeClaimed(w, req.WithContext(ctx))
		if w.deadline.IsZero() != (timeout > 0) {
			t.Errorf("listener timeout %s: unexpected relay read deadline %s", timeout, w.deadline)
		}
	}
}

func embeddedFixture(t *testing.T) (*Server, config.Profile) {
	t.Helper()
	cfg := config.Defaults()
	cfg.PublicHostname, cfg.BasePath = "proxy.example.test", "hidden/v1"
	p := config.Profile{Name: "embedded", Capability: [32]byte{0xab, 9}}
	cfg.Profiles = []config.Profile{p}
	server, err := NewEmbedded(cfg, [32]byte{33}, func(*http.Request) (string, error) { return "192.0.2.4", nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Shutdown)
	return server, p
}

func TestEmbeddedMetadataIsolation(t *testing.T) {
	s, p := embeddedFixture(t)
	path := "https://proxy.example.test" + s.base
	ticket, err := s.manager.IssueBootstrap(&p, "192.0.2.4")
	if err != nil {
		t.Fatal(err)
	}
	capability := config.CapabilityString(p.Capability)
	for _, place := range []string{"query", "escaped credential", "rewritten target", "header", "subprotocol", "host"} {
		t.Run(place, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, path+"public", nil)
			switch place {
			case "query":
				r.URL.RawQuery = "search=" + ticket
			case "escaped credential":
				r.URL.RawQuery = "q=%" + strings.ToUpper("5f") + url.QueryEscape(ticket)
			case "rewritten target":
				r.RequestURI += "?previous=" + capability
			case "header":
				r.Header.Set("X-Other", "prefix."+ticket+".suffix")
			case "subprotocol":
				r.Header.Set("Sec-WebSocket-Protocol", webSocketProtocolPrefix+ticket)
			case "host":
				r.Host = ticket + ".example.test"
			}
			if !s.ClaimsRequest(r) {
				t.Fatal("internal credential could reach fallback")
			}
			w := httptest.NewRecorder()
			s.ServeClaimed(w, r)
			if w.Code != http.StatusNotFound || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("invalid internal request returned %d", w.Code)
			}
			if strings.Contains(w.Body.String(), ticket) || strings.Contains(w.Body.String(), capability) {
				t.Fatal("denial reflected a credential")
			}
		})
	}
	r := httptest.NewRequest(http.MethodPost, path+"api/v1/session", strings.NewReader(ticket))
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("A", 43))
	if s.ClaimsRequest(r) {
		t.Fatal("an unrelated request was intercepted")
	}
	body, err := io.ReadAll(r.Body)
	if err != nil || string(body) != ticket {
		t.Fatal("classification consumed the public request body")
	}
}

func TestEmbeddedCredentialAtEveryAlignment(t *testing.T) {
	s, profile := embeddedFixture(t)
	ticket, err := s.manager.IssueBootstrap(&profile, "192.0.2.4")
	if err != nil {
		t.Fatal(err)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for _, token := range []string{ticket, config.CapabilityString(profile.Capability)} {
		last := strings.IndexByte(alphabet, token[len(token)-1])
		noncanonical := token[:len(token)-1] + string(alphabet[last|3])
		for offset := range 64 {
			prefix := strings.Repeat("A", offset)
			guard := metadataGuard{manager: s.manager}
			if !guard.has("short-runs./" + prefix + noncanonical + "QkD") {
				t.Errorf("plain field did not retain a credential at offset %d", offset)
			}
			if !guard.has("invalid%z!" + prefix + "%41" + noncanonical + "QkD") {
				t.Errorf("field with percent encoding did not retain a credential at offset %d", offset)
			}
			if guard.has(prefix + "!" + strings.Repeat("A", len(token))) {
				t.Errorf("an unrelated field was claimed at offset %d", offset)
			}
		}
	}
}

type unreadableBody struct{ reads int }

func (b *unreadableBody) Read([]byte) (int, error) {
	b.reads++
	return 0, errors.New("unexpected read")
}
func (*unreadableBody) Close() error { return nil }

func TestEmbeddedBootstrapAndSession(t *testing.T) {
	s, p := embeddedFixture(t)
	base := "https://proxy.example.test" + s.base
	get := httptest.NewRequest(http.MethodGet, base+"?bridge="+config.CapabilityString(p.Capability), nil)
	if !s.ClaimsRequest(get) {
		t.Fatal("bridge was not claimed")
	}
	w := httptest.NewRecorder()
	s.ServeClaimed(w, get)
	if w.Code != http.StatusOK || w.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("bridge status %d", w.Code)
	}
	_, js, found := strings.Cut(w.Body.String(), ",bootstrap=\"")
	ticket, _, end := strings.Cut(js, "\"")
	if !found || !end || len(ticket) != 43 {
		t.Fatal("bridge lacks a bootstrap token")
	}
	post := func(route, token string, data []byte) *http.Request {
		r := httptest.NewRequest(http.MethodPost, base+"api/v1/"+route, bytes.NewReader(data))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", binaryBody)
		return r
	}
	hello := frame.Encode(frame.Hello, 0, []byte{1})
	interrupted := post("session", ticket, hello)
	interrupted.Body = io.NopCloser(&interruptedHelloReader{hello: hello})
	deniedHello := httptest.NewRecorder()
	s.ServeClaimed(deniedHello, interrupted)
	if deniedHello.Code != http.StatusNotFound || s.manager.Capacity().Sessions != 0 {
		t.Fatalf("interrupted HELLO returned %d and allocated %d sessions",
			deniedHello.Code, s.manager.Capacity().Sessions)
	}
	for _, header := range []struct{ name, value string }{
		{"Content-Encoding", "gzip"},
		{"Cookie", "site=test"},
	} {
		r := post("session", ticket, hello)
		body := &unreadableBody{}
		r.Body = body
		r.Header[header.name] = []string{"", header.value}
		denied := httptest.NewRecorder()
		s.ServeClaimed(denied, r)
		if denied.Code != http.StatusNotFound || body.reads != 0 {
			t.Errorf("secondary %s was accepted: status %d, body reads %d", header.name, denied.Code, body.reads)
		}
	}
	create := httptest.NewRecorder()
	s.ServeClaimed(create, post("session", ticket, hello))
	active := create.Header().Get("X-Session-Token")
	if create.Code != http.StatusOK || active == "" || !bytes.Equal(create.Body.Bytes(), frame.Encode(frame.Welcome, 0, nil)) {
		t.Fatalf("session establishment returned %d", create.Code)
	}
	retry := httptest.NewRecorder()
	s.ServeClaimed(retry, post("session", ticket, hello))
	if retry.Header().Get("X-Session-Token") != active {
		t.Fatal("bootstrap retry issued a different session")
	}
	body := &unreadableBody{}
	wrongRole := post("session", active, nil)
	wrongRole.Body = body
	denied := httptest.NewRecorder()
	s.ServeClaimed(denied, wrongRole)
	if denied.Code != http.StatusNotFound || body.reads != 0 {
		t.Fatal("session endpoint read a body before bootstrap authentication")
	}
	for range 2 {
		r := post("session", active, nil)
		r.Method = http.MethodDelete
		r.Header.Del("Content-Type")
		result := httptest.NewRecorder()
		s.ServeClaimed(result, r)
		if result.Code != http.StatusNoContent {
			t.Fatalf("session delete returned %d", result.Code)
		}
	}
	if !s.ClaimsRequest(post("down", active, nil)) {
		t.Fatal("retired token escaped to fallback")
	}
}

type interruptedHelloReader struct {
	hello []byte
}

func (r *interruptedHelloReader) Read(p []byte) (int, error) {
	if len(r.hello) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.hello)
	r.hello = r.hello[n:]
	if len(r.hello) == 0 {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}
