package tproxy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/filestorage"
	"github.com/love4taylor/caddy-tproxy/internal/config"
	"github.com/love4taylor/caddy-tproxy/internal/server"
)

func TestConfiguredHostRelays(t *testing.T) {
	const missingHostname = "tproxy requires an explicit hostname"
	tests := []struct {
		name, caddyfile, routes, wantErr string
		hosts                            []string
	}{
		{
			name:      "all site addresses",
			caddyfile: "A.Example.com, b.example.com {\n\ttproxy {\n\t\tsecret_file %q\n\t}\n}\n",
			hosts:     []string{"a.example.com", "b.example.com"},
		},
		{
			name:      "explicit directive argument",
			caddyfile: "a.example.com, b.example.com {\n\ttproxy b.example.com {\n\t\tsecret_file %q\n\t}\n}\n",
			hosts:     []string{"b.example.com"},
		},
		{
			name: "two Caddyfile sites with the same handler configuration",
			caddyfile: "a.example.com {\n\ttproxy {\n\t\tsecret_file %[1]q\n\t}\n}\n" +
				"b.example.com {\n\ttproxy {\n\t\tsecret_file %[1]q\n\t}\n}\n",
			hosts: []string{"a.example.com", "b.example.com"},
		},
		{
			name:      "port-only site",
			caddyfile: ":443 {\n\ttproxy {\n\t\tsecret_file %q\n\t}\n}\n",
			wantErr:   missingHostname,
		},
		{
			name: "JSON nested routes and matcher alternatives",
			routes: `[{"match":[{"host":["a.example.com","b.example.com","c.example.com"]}],"handle":[{
				"handler":"subroute","routes":[{"match":[{"host":["a.example.com"]},{"host":["c.example.com","other.example.com"]}],
				"handle":[{"handler":"tproxy","secret_file":%q}]}]
			}]}]`,
			hosts: []string{"a.example.com", "c.example.com"},
		},
		{
			name: "concrete hosts in a wildcard site",
			routes: `[{"match":[{"host":["*.example.com"]}],"handle":[{"handler":"subroute","routes":[{
				"match":[{"host":["a.example.com","b.example.com","x.other.com"]}],
				"handle":[{"handler":"tproxy","secret_file":%q}]}]}]}]`,
			hosts: []string{"a.example.com", "b.example.com"},
		},
		{
			name: "explicit JSON override",
			routes: `[{"match":[{"host":["a.example.com","b.example.com"]}],
				"handle":[{"handler":"tproxy","hostname":"a.example.com","secret_file":%q}]}]`,
			hosts: []string{"a.example.com"},
		},
		{
			name: "wildcard only",
			routes: `[{"match":[{"host":["*.example.com"]}],
				"handle":[{"handler":"tproxy","secret_file":%q}]}]`,
			wantErr: missingHostname,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			secret := filepath.Join(dir, "tproxy.secret")
			if err := os.WriteFile(secret, []byte("00112233445566778899aabbccddeeff"), 0o600); err != nil {
				t.Fatal(err)
			}
			var data []byte
			if tt.caddyfile != "" {
				adapter := caddyconfig.GetAdapter("caddyfile")
				var err error
				data, _, err = adapter.Adapt(fmt.Appendf([]byte("{\n\tauto_https off\n}\n\n"), tt.caddyfile, secret), nil)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				routes := fmt.Sprintf(tt.routes, secret)
				data = fmt.Appendf(nil, `{"apps":{"http":{"servers":{"test":{
					"listen":[":443"],"automatic_https":{"disable":true},"routes":%s
				}}}}}`, routes)
			}
			var cfg caddy.Config
			if err := json.Unmarshal(data, &cfg); err != nil {
				t.Fatal(err)
			}
			cfg.StorageRaw = fmt.Appendf(nil, `{"module":"file_system","root":%q}`, dir)
			err := caddy.Validate(&cfg)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("validate error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assertHostSigningKeys(t, dir, tt.hosts)
		})
	}
}

func assertHostSigningKeys(t *testing.T, dir string, hostnames []string) {
	t.Helper()
	keyDir := filepath.Join(dir, "tproxy", "token_keys")
	entries, err := os.ReadDir(keyDir)
	if err != nil {
		t.Fatal(err)
	}
	var got, want []string
	for _, entry := range entries {
		got = append(got, entry.Name())
	}
	for _, host := range hostnames {
		scope := sha256.Sum256([]byte(host + "\n/"))
		want = append(want, fmt.Sprintf("%x", scope))
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("stored keys = %v, want %v for %v", got, want, hostnames)
	}
}

func TestHostRelaysIsolateCredentials(t *testing.T) {
	const first, second = "a.example.com", "b.example.com"
	module := &Handler{hosts: make(map[string]*hostRelay)}
	capabilities := make(map[string]string)
	for _, hostname := range []string{first, second} {
		value := config.Defaults()
		value.PublicHostname = hostname
		capability := config.DeriveCapability(hostname, "", []byte("test secret key!"))
		value.Profiles = []config.Profile{{Capability: capability}}
		relay, err := server.NewEmbedded(value, [32]byte{7}, clientIP)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(relay.Shutdown)
		module.hosts[hostname] = &hostRelay{relay: relay}
		capabilities[hostname] = config.CapabilityString(capability)
	}
	fallback := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusAccepted)
		return nil
	})
	for _, tt := range []struct {
		host, credential string
		status           int
	}{
		{first, capabilities[first], http.StatusOK},
		{second, capabilities[second], http.StatusOK},
		{first, capabilities[second], http.StatusNotFound},
		{"unused.example.com", capabilities[first], http.StatusNotFound},
		{first, "", http.StatusAccepted},
	} {
		r := httptest.NewRequest(http.MethodGet, "https://"+tt.host+":443/?bridge="+tt.credential, nil)
		r.TLS.HandshakeComplete = true
		w := httptest.NewRecorder()
		if err := module.ServeHTTP(w, r, fallback); err != nil || w.Code != tt.status {
			t.Fatalf("%s: HTTP %d, want %d, error %v", tt.host, w.Code, tt.status, err)
		}
		if tt.status == http.StatusOK && !strings.Contains(w.Body.String(), `relayBase="https://`+tt.host+`/"`) {
			t.Fatalf("bridge uses the wrong relay URL for %s", tt.host)
		}
		if tt.status == http.StatusNotFound && w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("rejected request for %s was not marked no-store", tt.host)
		}
	}
}
