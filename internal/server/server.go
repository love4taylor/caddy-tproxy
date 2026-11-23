package server

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/love4taylor/caddy-tproxy/internal/bridge"
	"github.com/love4taylor/caddy-tproxy/internal/config"
	"github.com/love4taylor/caddy-tproxy/internal/session"
)

type Server struct {
	config           config.Config
	base             string
	manager          *session.Manager
	bodyReadDeadline time.Duration
	clientIP         func(*http.Request) (string, error)
}

func NewEmbedded(cfg config.Config, key [sha256.Size]byte, address func(*http.Request) (string, error)) (*Server, error) {
	if address == nil {
		return nil, errors.New("WEB relay requires a client address provider")
	}
	if err := session.ValidateBudget(cfg); err != nil {
		return nil, err
	}
	return &Server{config: cfg, base: cfg.Base(), manager: session.NewManager(cfg, key),
		bodyReadDeadline: 30 * time.Second, clientIP: address}, nil
}

func (s *Server) Shutdown() { s.manager.Shutdown() }

func (s *Server) ClaimsRequest(r *http.Request) bool { return s.hasInternalSecret(r) }

func (s *Server) ServeClaimed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.ContentLength != 0 {
		listener, _ := r.Context().Value(http.ServerContextKey).(*http.Server)
		if listener == nil || listener.ReadTimeout <= 0 {
			_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(s.bodyReadDeadline))
		}
	}
	host := s.config.PublicHostname
	path := r.URL.EscapedPath()
	relative, inside := strings.CutPrefix(path, s.base)
	if !inside || path != r.URL.Path || (r.Host != host && r.Host != host+":443") {
		http.NotFound(w, r)
		return
	}
	switch relative {
	case "api/v1/session", "api/v1/up", "api/v1/down", "api/v1/ws":
		s.serveAPI(w, r, relative)
		return
	case "":
		if profile := s.bridgeProfile(r); profile != nil && s.writeBridge(w, r, profile) {
			return
		}
	}
	http.NotFound(w, r)
}

func (s *Server) writeBridge(w http.ResponseWriter, r *http.Request, profile *config.Profile) bool {
	address, err := s.clientIP(r)
	if err != nil {
		return false
	}
	ticket, err := s.manager.IssueBootstrap(profile, address)
	if err != nil {
		return false
	}
	mode := string(profile.CarrierMode.WithDefault())
	limits := s.config.Limits
	page, err := bridge.Render(s.config.PublicHostname, s.config.BasePath, ticket, mode, limits.CarrierBatchBytes, limits.MaxFramePayload)
	if err != nil {
		return false
	}
	headers := w.Header()
	headers.Set("Content-Security-Policy", page.CSP)
	headers.Set("Content-Type", "text/html; charset=utf-8")
	headers.Set("Content-Length", strconv.Itoa(len(page.Body)))
	headers.Set("Referrer-Policy", "no-referrer")
	headers.Set("Permissions-Policy", bridge.PermissionsPolicy)
	headers.Set("X-DNS-Prefetch-Control", "off")
	headers.Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(page.Body)
	return true
}

func (s *Server) ChangeBufferBudget(delta int) bool { return s.manager.ChangeBufferBudget(delta) }

func (s *Server) Capacity() session.Capacity { return s.manager.Capacity() }

func (s *Server) Metrics() session.Metrics { return s.manager.Metrics() }
