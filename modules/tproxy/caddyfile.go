package tproxy

import (
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/love4taylor/caddy-tproxy/internal/config"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("tproxy", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("tproxy", httpcaddyfile.Before, "rewrite")
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	handler := new(Handler)
	return handler, handler.UnmarshalCaddyfile(h.Dispenser)
}

func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		h.Hostname = d.Val()
		if h.Hostname == "" || d.NextArg() {
			return d.ArgErr()
		}
	}
	fields := map[string]*string{
		"secret_file":    &h.SecretFile,
		"carrier":        &h.Carrier,
		"base_path":      &h.BasePath,
		"public_ip":      &h.PublicIP,
		"token_key_file": &h.TokenKeyFile,
	}
	for d.NextBlock(0) {
		name := d.Val()
		switch name {
		case "reconnect_grace":
			var raw string
			if h.ReconnectGrace != 0 || !d.AllArgs(&raw) {
				return d.ArgErr()
			}
			value, err := caddy.ParseDuration(raw)
			if err != nil || value <= 0 {
				return d.Err("tproxy reconnect_grace requires a positive duration")
			}
			h.ReconnectGrace = caddy.Duration(value)
		case "limits":
			if h.Limits != nil || d.NextArg() {
				return d.ArgErr()
			}
			var err error
			h.Limits, err = parseLimits(d, new(config.Limits))
			if err != nil {
				return err
			}
			if _, set := h.Limits["max_header_bytes"]; set {
				return d.Err("set max_header_bytes on the Caddy listener using servers max_header_size")
			}
		case "profile":
			args := d.RemainingArgs()
			if len(args) < 2 || len(args) > 3 {
				return d.ArgErr()
			}
			profile := Profile{Name: args[0], SecretFile: args[1]}
			if len(args) == 3 {
				profile.Carrier = args[2]
			}
			var err error
			profile.Limits, err = parseLimits(d, new(config.ProfileLimits))
			if err != nil {
				return err
			}
			h.Profiles = append(h.Profiles, profile)
		default:
			field, ok := fields[name]
			if !ok {
				return d.Errf("unknown or repeated tproxy option %q", name)
			}
			if !d.AllArgs(field) {
				return d.ArgErr()
			}
			delete(fields, name)
		}
	}
	return nil
}

func parseLimits(d *caddyfile.Dispenser, target any) (map[string]int, error) {
	limits := make(map[string]int)
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		name := d.Val()
		var raw string
		if !d.AllArgs(&raw) {
			return nil, d.ArgErr()
		}
		if _, exists := limits[name]; exists {
			return nil, d.Errf("repeated tproxy limit %q", name)
		}
		value, err := strconv.Atoi(raw)
		if err != nil {
			return nil, d.Errf("tproxy limit %q requires an integer", name)
		}
		limits[name] = value
	}
	if err := applyLimitOverrides(limits, target); err != nil {
		return nil, d.Errf("tproxy limits: %v", err)
	}
	return limits, nil
}

var _ caddyfile.Unmarshaler = (*Handler)(nil)
