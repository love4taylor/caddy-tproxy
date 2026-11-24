package tproxy

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/love4taylor/caddy-tproxy/internal/config"
)

func inferRouteHostnames(ctx caddy.Context) []string {
	modules := ctx.Modules()
	appIndex := slices.IndexFunc(modules, func(module caddy.Module) bool {
		_, ok := module.(*caddyhttp.App)
		return ok
	})
	if appIndex < 0 || ctx.Context == nil {
		return nil
	}
	srv, ok := ctx.Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server)
	if !ok {
		return nil
	}

	var matchers []caddyhttp.MatcherSets
	routes := srv.Routes
	for _, module := range modules[appIndex+1:] {
		// Caddy provisions primary routes in order, clearing HandlersRaw after
		// each route completes. During its handlers' provisioning, the first
		// route with raw handlers is the one being loaded at this level.
		active := slices.IndexFunc(routes, func(route caddyhttp.Route) bool {
			return len(route.HandlersRaw) > 0
		})
		if active < 0 {
			return nil
		}
		matchers = append(matchers, routes[active].MatcherSets)
		switch module := module.(type) {
		case *Handler:
			return configuredHostnames(matchers)
		case *caddyhttp.Subroute:
			routes = module.Routes
		default:
			return nil
		}
	}
	return nil
}

func configuredHostnames(routes []caddyhttp.MatcherSets) []string {
	candidates := make(map[string]struct{})
	for _, sets := range routes {
		for _, set := range sets {
			for _, host := range hostMatcher(set) {
				if config.ValidateHostname(host) == nil {
					candidates[host] = struct{}{}
				}
			}
		}
	}
	request := (&http.Request{}).WithContext(context.WithValue(context.Background(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
	return slices.DeleteFunc(slices.Sorted(maps.Keys(candidates)), func(host string) bool {
		request.Host = host
		// Matcher sets are alternatives. Enclosing routes, however, must all
		// admit this hostname. Caddy evaluates the other matchers at request time.
		for _, sets := range routes {
			if len(sets) > 0 && !slices.ContainsFunc(sets, func(set caddyhttp.MatcherSet) bool {
				hosts := hostMatcher(set)
				return hosts == nil || hosts.Match(request) || slices.ContainsFunc(hosts, func(host string) bool {
					return strings.Contains(host, "{")
				})
			}) {
				return true
			}
		}
		return false
	})
}

func hostMatcher(set caddyhttp.MatcherSet) caddyhttp.MatchHost {
	for _, matcher := range set {
		switch matcher := matcher.(type) {
		case caddyhttp.MatchHost:
			return matcher
		case *caddyhttp.MatchHost:
			return *matcher
		}
	}
	return nil
}
