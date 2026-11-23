package tproxy

import (
	"context"
	"crypto/fips140"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/love4taylor/caddy-tproxy/internal/config"
	"github.com/love4taylor/caddy-tproxy/internal/server"
)

// Handler embeds the Telegram WEB relay and its MTProxy backend in Caddy.
type Handler struct {
	Hostname       string         `json:"hostname"`
	SecretFile     string         `json:"secret_file,omitempty"`
	Carrier        string         `json:"carrier,omitempty"`
	Profiles       []Profile      `json:"profiles,omitempty"`
	PublicIP       string         `json:"public_ip,omitempty"`
	BasePath       string         `json:"base_path,omitempty"`
	TokenKeyFile   string         `json:"token_key_file,omitempty"`
	Limits         map[string]int `json:"limits,omitempty"`
	ReconnectGrace caddy.Duration `json:"reconnect_grace,omitempty"`

	relay       *server.Server
	backend     *backend
	stopMetrics func()
	replayKeys  [][16]byte
}

type Profile struct {
	Name       string         `json:"name"`
	SecretFile string         `json:"secret_file"`
	Carrier    string         `json:"carrier,omitempty"`
	Limits     map[string]int `json:"limits,omitempty"`
}

func init() {
	caddy.RegisterModule(Handler{})
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.tproxy",
		New: func() caddy.Module { return new(Handler) },
	}
}

func (h *Handler) Provision(ctx caddy.Context) error {
	if fips140.Enforced() {
		return errors.New("tproxy cannot run under strict FIPS 140 enforcement because Telegram RPC requires MD5 and SHA-1")
	}
	value := config.Defaults()
	value.PublicHostname = h.Hostname
	value.BasePath = strings.TrimPrefix(h.BasePath, "/")
	if err := config.ValidateHostname(value.PublicHostname); err != nil {
		return fmt.Errorf("tproxy hostname: %w", err)
	}
	if err := config.ValidateBasePath(value.BasePath); err != nil {
		return fmt.Errorf("tproxy base_path: %w", err)
	}
	if _, set := h.Limits["max_header_bytes"]; set {
		return errors.New("tproxy max_header_bytes is set on the Caddy listener using servers max_header_size")
	}
	if err := applyLimitOverrides(h.Limits, &value.Limits); err != nil {
		return fmt.Errorf("tproxy limits: %w", err)
	}
	if err := value.Limits.Validate(); err != nil {
		return fmt.Errorf("tproxy limits: %w", err)
	}
	if h.ReconnectGrace < 0 {
		return errors.New("tproxy reconnect_grace must be positive")
	}
	if h.ReconnectGrace != 0 {
		value.Timeouts.ReconnectGrace = time.Duration(h.ReconnectGrace)
	}
	secrets, err := h.loadProfiles(&value)
	if err != nil {
		return err
	}

	key, err := h.signingKey(ctx, value.Base())
	if err != nil {
		return fmt.Errorf("tproxy signing key: %w", err)
	}

	var publicIP netip.Addr
	if h.PublicIP != "" {
		publicIP, err = netip.ParseAddr(h.PublicIP)
		if err != nil || !publicIPv4(publicIP) {
			return errors.New("tproxy public_ip must be a public IPv4 address")
		}
	}
	backend := newBackend(ctx, publicIP, ctx.Logger().Named("mtproxy"))
	replayKeys := make([][16]byte, 0, len(secrets))
	defer func() {
		for _, secret := range replayKeys {
			_, _ = handshakeWindows.Delete(secret)
		}
	}()
	for i := range value.Profiles {
		profile := &value.Profiles[i]
		secret := secrets[profile.Name]
		window, _ := handshakeWindows.LoadOrStore(secret, new(handshakeReplays))
		replays := window.(*handshakeReplays)
		replayKeys = append(replayKeys, secret)
		profile.DialBackend = func(ctx context.Context, ready func(error)) (net.Conn, error) {
			return backend.dial(ctx, secret, replays, ready)
		}
	}
	relay, err := server.NewEmbedded(value, key, clientIP)
	if err != nil {
		backend.close()
		return fmt.Errorf("tproxy relay: %w", err)
	}
	backend.buffer.shared = relay.ChangeBufferBudget
	backend.maxDials = min(defaultMiddleDials, value.Limits.MaxBackendDialsInFlight)
	if err := h.registerMetrics(ctx.GetMetricsRegistry(), relay, backend, value.Base()); err != nil {
		relay.Shutdown()
		backend.close()
		return fmt.Errorf("tproxy metrics: %w", err)
	}
	backend.start(ctx)
	h.backend, h.relay = backend, relay
	h.replayKeys, replayKeys = replayKeys, nil
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if !h.relay.ClaimsRequest(r) {
		return next.ServeHTTP(w, r)
	}
	// The URI and WebSocket subprotocol can contain reusable credentials.
	caddyhttp.SetVar(r.Context(), caddyhttp.LogSkipVar, true)
	if r.TLS == nil {
		w.Header().Set("Cache-Control", "no-store")
		http.NotFound(w, r)
		return nil
	}
	// RFC 8470 defines only the value 1. Treat any presence as early data.
	if !r.TLS.HandshakeComplete || len(r.Header.Values("Early-Data")) != 0 {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusTooEarly)
		return nil
	}
	h.relay.ServeClaimed(w, r)
	return nil
}

func (h *Handler) Cleanup() error {
	if h.stopMetrics != nil {
		h.stopMetrics()
	}
	if h.relay != nil {
		h.relay.Shutdown()
	}
	if h.backend != nil {
		h.backend.close()
	}
	for _, secret := range h.replayKeys {
		_, _ = handshakeWindows.Delete(secret)
	}
	h.replayKeys = nil
	return nil
}

func (h *Handler) loadProfiles(value *config.Config) (map[string][16]byte, error) {
	profiles := h.Profiles
	switch {
	case len(profiles) == 0 && h.SecretFile != "":
		profiles = []Profile{{Name: "default", SecretFile: h.SecretFile, Carrier: h.Carrier}}
	case len(profiles) == 0:
		return nil, errors.New("tproxy requires secret_file or at least one profile")
	case h.SecretFile != "" || h.Carrier != "":
		return nil, errors.New("tproxy profile cannot be combined with secret_file or carrier")
	case len(profiles) > value.Limits.MaxProfiles:
		return nil, fmt.Errorf("tproxy supports up to %d profiles", value.Limits.MaxProfiles)
	}

	secrets := make(map[string][16]byte, len(profiles))
	keys := make(map[[16]byte]struct{}, len(profiles))
	for _, profile := range profiles {
		if len(profile.Name) == 0 || len(profile.Name) > 64 {
			return nil, errors.New("tproxy profile name must contain 1–64 bytes")
		}
		if _, exists := secrets[profile.Name]; exists {
			return nil, fmt.Errorf("tproxy duplicate profile name %q", profile.Name)
		}
		carrier := config.CarrierMode(profile.Carrier).WithDefault()
		if !carrier.Valid() {
			return nil, fmt.Errorf("tproxy profile %q carrier must be https, https-lanes, websocket, or websocket-lanes", profile.Name)
		}
		var limits config.ProfileLimits
		if err := applyLimitOverrides(profile.Limits, &limits); err != nil {
			return nil, fmt.Errorf("tproxy profile %q limits: %w", profile.Name, err)
		}
		if err := limits.Validate(value.Limits); err != nil {
			return nil, fmt.Errorf("tproxy profile %q limits: %w", profile.Name, err)
		}
		secret, err := config.ReadClientSecret(profile.SecretFile)
		if err != nil {
			return nil, fmt.Errorf("tproxy profile %q secret_file: %w", profile.Name, err)
		}
		var key [16]byte
		copy(key[:], secret[len(secret)-len(key):])
		capability := config.DeriveCapability(value.PublicHostname, value.BasePath, secret)
		clear(secret)
		if _, exists := keys[key]; exists {
			return nil, fmt.Errorf("tproxy profile %q reuses an MTProxy secret", profile.Name)
		}
		keys[key] = struct{}{}
		secrets[profile.Name] = key
		value.Profiles = append(value.Profiles, config.Profile{
			Name:        profile.Name,
			CarrierMode: carrier,
			Capability:  capability,
			Limits:      limits.WithDefaults(value.Limits),
		})
	}
	return secrets, nil
}

func applyLimitOverrides(overrides map[string]int, limits any) error {
	if len(overrides) == 0 {
		return nil
	}
	for name := range overrides {
		if name != strings.ToLower(name) {
			return fmt.Errorf("limit name %q must be lowercase", name)
		}
	}
	data, err := json.Marshal(overrides)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(limits)
}

func (h *Handler) signingKey(ctx caddy.Context, base string) (key [sha256.Size]byte, err error) {
	if h.TokenKeyFile != "" {
		return config.ReadTokenKey(h.TokenKeyFile)
	}
	storage := ctx.Storage()
	// Hash the scope so host and base path form a single storage key.
	scope := sha256.Sum256([]byte(h.Hostname + "\n" + base))
	path := fmt.Sprintf("tproxy/token_keys/%x", scope)
	lock := fmt.Sprintf("tproxy-token-%x", scope)
	lockCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err = storage.Lock(lockCtx, lock); err != nil {
		return key, err
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		err = errors.Join(err, storage.Unlock(unlockCtx, lock))
	}()
	data, err := storage.Load(lockCtx, path)
	if errors.Is(err, fs.ErrNotExist) {
		rand.Read(key[:])
		return key, storage.Store(lockCtx, path, key[:])
	}
	if err != nil {
		return key, err
	}
	defer clear(data)
	if len(data) != len(key) {
		return key, errors.New("stored key must contain exactly 32 bytes")
	}
	copy(key[:], data)
	return key, nil
}

func clientIP(r *http.Request) (string, error) {
	value, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	if value == "" {
		var err error
		value, _, err = net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return "", err
		}
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return "", err
	}
	return addr.WithZone("").Unmap().String(), nil
}

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
