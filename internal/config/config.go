package config

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"time"
)

type CarrierMode string

const (
	CarrierHTTPS          CarrierMode = "https"
	CarrierWebSocket      CarrierMode = "websocket"
	CarrierHTTPSLanes     CarrierMode = "https-lanes"
	CarrierWebSocketLanes CarrierMode = "websocket-lanes"
)

func (m CarrierMode) Valid() bool {
	switch m {
	case CarrierHTTPS, CarrierWebSocket, CarrierHTTPSLanes, CarrierWebSocketLanes:
		return true
	}
	return false
}

func (m CarrierMode) WithDefault() CarrierMode {
	if m == "" {
		return CarrierHTTPS
	}
	return m
}

type Limits struct {
	MaxHeaderBytes    int `json:"max_header_bytes"`
	MaxBodyBytes      int `json:"max_body_bytes"`
	CarrierBatchBytes int `json:"carrier_batch_bytes"`
	MaxFramePayload   int `json:"max_frame_payload"`

	MaxProfiles            int `json:"max_profiles"`
	MaxBootstrapsGlobal    int `json:"max_bootstraps_global"`
	MaxBootstrapsPerIP     int `json:"max_bootstraps_per_ip"`
	NewBootstrapsPerMinute int `json:"new_bootstraps_per_minute"`
	NewBootstrapsBurst     int `json:"new_bootstraps_burst"`
	MaxSessionsGlobal      int `json:"max_sessions_global"`
	MaxSessionsPerIP       int `json:"max_sessions_per_ip"`
	NewSessionsPerMinute   int `json:"new_sessions_per_minute"`
	NewSessionsBurst       int `json:"new_sessions_burst"`

	MaxStreamsGlobal        int `json:"max_streams_global"`
	MaxStreamsPerSession    int `json:"max_streams_per_session"`
	MaxBackendDialsInFlight int `json:"max_backend_dials_in_flight"`
	NewStreamsPerMinute     int `json:"new_streams_per_minute"`
	NewStreamsBurst         int `json:"new_streams_burst"`
	MaxClosedStreamIDs      int `json:"max_closed_stream_ids"`

	MaxPendingGlobal          int `json:"max_pending_global"`
	MaxPendingItemsGlobal     int `json:"max_pending_items_global"`
	MaxPendingPerSession      int `json:"max_pending_per_session"`
	MaxPendingItemsPerSession int `json:"max_pending_items_per_session"`
}

type Timeouts struct {
	BootstrapLifetime time.Duration `json:"bootstrap_lifetime"`
	ReconnectGrace    time.Duration `json:"reconnect_grace"`
	LongPoll          time.Duration `json:"long_poll"`
}

type Config struct {
	PublicHostname string    `json:"public_hostname"`
	BasePath       string    `json:"base_path"`
	Limits         Limits    `json:"limits"`
	Timeouts       Timeouts  `json:"timeouts"`
	Profiles       []Profile `json:"-"`
}

type ProfileLimits struct {
	MaxSessions          int `json:"max_sessions"`
	NewSessionsPerMinute int `json:"new_sessions_per_minute"`
	NewSessionsBurst     int `json:"new_sessions_burst"`

	MaxStreams              int `json:"max_streams"`
	MaxStreamsPerSession    int `json:"max_streams_per_session"`
	MaxBackendDialsInFlight int `json:"max_backend_dials_in_flight"`
	NewStreamsPerMinute     int `json:"new_streams_per_minute"`
	NewStreamsBurst         int `json:"new_streams_burst"`
	MaxPendingPerSession    int `json:"max_pending_per_session"`
}

type Profile struct {
	Name        string
	CarrierMode CarrierMode
	Capability  [sha256.Size]byte
	Limits      ProfileLimits
	DialBackend func(ctx context.Context, ready func(error)) (net.Conn, error)
}

func Defaults() Config {
	const (
		kibibyte = 1 << 10
		mebibyte = 1 << 20
		grace    = 2 * time.Minute
	)
	return Config{
		Limits: Limits{
			MaxHeaderBytes:    16 * kibibyte,
			MaxFramePayload:   mebibyte,
			MaxBodyBytes:      MaxCarrierBatchBytes,
			CarrierBatchBytes: MaxCarrierBatchBytes,

			MaxProfiles:            32,
			MaxBootstrapsGlobal:    512,
			NewBootstrapsPerMinute: 1200,
			NewBootstrapsBurst:     256,
			MaxSessionsGlobal:      128,
			NewSessionsPerMinute:   600,
			NewSessionsBurst:       128,

			MaxStreamsPerSession:    128,
			MaxStreamsGlobal:        4096,
			MaxBackendDialsInFlight: 256,
			NewStreamsPerMinute:     6000,
			NewStreamsBurst:         512,
			MaxClosedStreamIDs:      4096,

			MaxPendingPerSession:      32 * mebibyte,
			MaxPendingItemsPerSession: 16 * kibibyte,
			MaxPendingGlobal:          512 * mebibyte,
			MaxPendingItemsGlobal:     256 * kibibyte,
		},
		Timeouts: Timeouts{
			BootstrapLifetime: grace,
			ReconnectGrace:    grace,
			LongPoll:          25 * time.Second,
		},
	}
}

func (l Limits) Validate() error {
	if l.CarrierBatchBytes > MaxCarrierBatchBytes {
		return errors.New("carrier_batch_bytes exceeds the 2 MiB desktop message limit")
	}
	if l.MaxFramePayload < 4 {
		return errors.New("max_frame_payload must fit a four-byte WINDOW credit increment")
	}
	if l.MaxHeaderBytes < 4096 || l.MaxBodyBytes < 1024 ||
		l.MaxFramePayload > 1<<20 || l.CarrierBatchBytes < 256<<10 || l.CarrierBatchBytes > l.MaxBodyBytes {
		return errors.New("invalid HTTP or frame limits")
	}
	for _, pair := range [][2]int{
		{l.MaxPendingPerSession, l.MaxPendingGlobal},
		{l.MaxPendingItemsPerSession, l.MaxPendingItemsGlobal},
		{l.MaxStreamsPerSession, l.MaxStreamsGlobal},
		{l.MaxBackendDialsInFlight, l.MaxStreamsGlobal},
	} {
		if pair[0] < 1 || pair[0] > pair[1] {
			return errors.New("resource limits must be positive and fit the corresponding global limit")
		}
	}
	for _, pair := range [][2]int{
		{l.MaxSessionsPerIP, l.MaxSessionsGlobal},
		{l.MaxBootstrapsPerIP, l.MaxBootstrapsGlobal},
	} {
		if pair[1] < 1 || pair[0] < 0 || pair[0] > pair[1] {
			return errors.New("per-IP limits must be between zero and the corresponding global limit")
		}
	}
	for _, v := range []int{l.MaxProfiles, l.MaxClosedStreamIDs,
		l.NewBootstrapsPerMinute, l.NewBootstrapsBurst, l.NewSessionsPerMinute,
		l.NewSessionsBurst, l.NewStreamsPerMinute, l.NewStreamsBurst} {
		if v < 1 {
			return errors.New("resource limits and rate limits must be positive")
		}
	}
	return nil
}

func inherit(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

func (p ProfileLimits) WithDefaults(l Limits) ProfileLimits {
	streams := inherit(p.MaxStreams, l.MaxStreamsGlobal)
	return ProfileLimits{
		MaxSessions:             inherit(p.MaxSessions, l.MaxSessionsGlobal),
		MaxStreams:              streams,
		MaxBackendDialsInFlight: inherit(p.MaxBackendDialsInFlight, min(l.MaxBackendDialsInFlight, streams)),
		NewSessionsPerMinute:    inherit(p.NewSessionsPerMinute, l.NewSessionsPerMinute),
		NewSessionsBurst:        inherit(p.NewSessionsBurst, l.NewSessionsBurst),
		NewStreamsPerMinute:     inherit(p.NewStreamsPerMinute, l.NewStreamsPerMinute),
		NewStreamsBurst:         inherit(p.NewStreamsBurst, l.NewStreamsBurst),
		MaxStreamsPerSession:    inherit(p.MaxStreamsPerSession, min(l.MaxStreamsPerSession, streams)),
		MaxPendingPerSession:    inherit(p.MaxPendingPerSession, l.MaxPendingPerSession),
	}
}

func (p ProfileLimits) Validate(l Limits) error {
	streams := inherit(p.MaxStreams, l.MaxStreamsGlobal)
	for _, limit := range []struct {
		name           string
		value, ceiling int
	}{
		{"max_sessions", p.MaxSessions, l.MaxSessionsGlobal},
		{"max_streams", p.MaxStreams, l.MaxStreamsGlobal},
		{"max_backend_dials_in_flight", p.MaxBackendDialsInFlight, min(l.MaxBackendDialsInFlight, streams)},
		{"new_sessions_per_minute", p.NewSessionsPerMinute, l.NewSessionsPerMinute},
		{"new_sessions_burst", p.NewSessionsBurst, l.NewSessionsBurst},
		{"new_streams_per_minute", p.NewStreamsPerMinute, l.NewStreamsPerMinute},
		{"new_streams_burst", p.NewStreamsBurst, l.NewStreamsBurst},
		{"max_streams_per_session", p.MaxStreamsPerSession, min(l.MaxStreamsPerSession, streams)},
		{"max_pending_per_session", p.MaxPendingPerSession, l.MaxPendingPerSession},
	} {
		if limit.value < 0 || limit.value > limit.ceiling {
			return fmt.Errorf("%s must be between 0 and %d", limit.name, limit.ceiling)
		}
	}
	return nil
}
