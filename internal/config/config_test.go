package config

import (
	"strings"
	"testing"
	"time"
)

func TestEmbeddedDefaults(t *testing.T) {
	cfg := Defaults()
	if err := cfg.Limits.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Timeouts.ReconnectGrace != 2*time.Minute {
		t.Fatalf("reconnect grace = %v", cfg.Timeouts.ReconnectGrace)
	}
	if (CarrierMode("")).WithDefault() != CarrierHTTPS {
		t.Fatal("an unset carrier must use HTTPS")
	}
}

func TestLimitRelationships(t *testing.T) {
	for _, change := range []struct {
		name string
		set  func(*Limits)
	}{
		{"desktop batch cap", func(l *Limits) { l.CarrierBatchBytes++; l.MaxBodyBytes++ }},
		{"body cannot contain batch", func(l *Limits) { l.MaxBodyBytes = l.CarrierBatchBytes - 1 }},
		{"frame cannot contain WINDOW", func(l *Limits) { l.MaxFramePayload = 3 }},
		{"session byte budget", func(l *Limits) { l.MaxPendingPerSession = l.MaxPendingGlobal + 1 }},
		{"global admission", func(l *Limits) { l.MaxSessionsGlobal = 0 }},
		{"per-IP bootstrap limit", func(l *Limits) { l.MaxBootstrapsPerIP = -1 }},
		{"rate limit", func(l *Limits) { l.NewStreamsBurst = 0 }},
	} {
		t.Run(change.name, func(t *testing.T) {
			limits := Defaults().Limits
			change.set(&limits)
			if limits.Validate() == nil {
				t.Fatal("unsafe limit accepted")
			}
		})
	}
}

func TestProfileInheritance(t *testing.T) {
	global := Defaults().Limits
	profile := ProfileLimits{MaxStreams: 17, NewStreamsBurst: 9}
	if err := profile.Validate(global); err != nil {
		t.Fatal(err)
	}
	got := profile.WithDefaults(global)
	if got.MaxStreams != 17 || got.MaxBackendDialsInFlight != 17 || got.MaxStreamsPerSession != 17 ||
		got.NewStreamsBurst != 9 || got.NewSessionsPerMinute != global.NewSessionsPerMinute {
		t.Fatalf("unexpected effective limits: %+v", got)
	}
	profile.MaxBackendDialsInFlight = 18
	if err := profile.Validate(global); err == nil {
		t.Fatal("profile dial quota exceeds the number of allowed streams")
	}
	profile.MaxStreams = global.MaxStreamsGlobal + 1
	if err := profile.Validate(global); err == nil {
		t.Fatal("profile stream quota exceeds the global quota")
	}
}

func TestHostnameCanonicalForm(t *testing.T) {
	for _, domain := range []string{"nested.host.example", "xn--bcher-kva.example", strings.Repeat("x", 63) + ".net"} {
		if err := ValidateHostname(domain); err != nil {
			t.Errorf("rejected DNS name %q: %v", domain, err)
		}
	}
	for _, domain := range []string{"localhost", "Loop.example", "01.2.3.4", "127.0.0.1", "[::1]", "p.example:443", "p.example.", "p..example", "-x.example", "a/b.net", "a_.net", "é.example", strings.Repeat("x", 64) + ".net"} {
		if err := ValidateHostname(domain); err == nil {
			t.Errorf("accepted noncanonical DNS name %q", domain)
		}
	}
}

func TestSecretMarkerIsLengthDependent(t *testing.T) {
	plain, err := DecodeSecret([]byte("ee0102030405060708090a0b0c0d0e0f"))
	if err != nil || len(plain) != 16 || plain[0] != 0xee {
		t.Fatalf("valid plain key rejected: %v", err)
	}
	if _, err := DecodeSecret([]byte("ee000102030405060708090a0b0c0d0e0f")); err == nil {
		t.Fatal("FakeTLS marker accepted for WEB proxy")
	}
}
