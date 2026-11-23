package tproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

const (
	telegramConfigHost = "core.telegram.org"
	telegramConfigURL  = "https://" + telegramConfigHost + "/getProxyConfig"
	telegramSecretURL  = "https://" + telegramConfigHost + "/getProxySecret"
	routingCacheKey    = "tproxy/telegram-routing.json"
	maxRoutingFile     = 256 << 10
	maxRoutingCache    = 2 * maxRoutingFile // Includes Base64 expansion and the JSON envelope.
)

type routingFiles struct {
	Config []byte
	Secret []byte
}

type routingConfig struct {
	fallback int16
	dcs      map[int16][]netip.AddrPort
	secret   [128]byte
}

func checkRoutingRedirect(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" || req.URL.Host != telegramConfigHost || len(via) >= 10 {
		return errors.New("invalid Telegram configuration redirect")
	}
	return nil
}

func (r *routingConfig) targets(dc int16) []netip.AddrPort {
	if out := r.dcs[dc]; len(out) != 0 {
		return out
	}
	return r.dcs[r.fallback]
}

func (r *routingConfig) contains(target middleTarget) bool {
	if target.secret != r.secret {
		return false
	}
	for _, endpoints := range r.dcs {
		for _, endpoint := range endpoints {
			if endpoint == target.address {
				return true
			}
		}
	}
	return false
}

func parseRouting(files routingFiles) (*routingConfig, error) {
	if len(files.Secret) != 128 || len(files.Config) > maxRoutingFile {
		return nil, errors.New("invalid Telegram routing file size")
	}
	out := &routingConfig{dcs: make(map[int16][]netip.AddrPort)}
	copy(out.secret[:], files.Secret)
	scanner := bufio.NewScanner(bytes.NewReader(files.Config))
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasSuffix(line, ";") {
			return nil, errors.New("missing semicolon in Telegram route")
		}
		fields := strings.Fields(strings.TrimSuffix(line, ";"))
		if len(fields) < 2 {
			return nil, errors.New("incomplete Telegram route")
		}
		dc, err := strconv.ParseInt(fields[1], 10, 16)
		if err != nil || dc == 0 {
			return nil, errors.New("invalid Telegram DC number")
		}
		switch {
		case fields[0] == "default" && len(fields) == 2 && out.fallback == 0:
			out.fallback = int16(dc)
		case fields[0] == "proxy_for" && len(fields) == 3:
			addr, err := netip.ParseAddrPort(fields[2])
			ip := addr.Addr().Unmap()
			if err != nil || addr.Port() == 0 || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.Zone() != "" {
				return nil, errors.New("invalid Telegram endpoint")
			}
			if ip.Is4() {
				if !publicIPv4(ip) {
					return nil, errors.New("invalid Telegram IPv4 endpoint")
				}
				out.dcs[int16(dc)] = append(out.dcs[int16(dc)], netip.AddrPortFrom(ip, addr.Port()))
			}
		default:
			return nil, errors.New("unexpected Telegram route directive")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if out.fallback == 0 || len(out.dcs[out.fallback]) == 0 {
		return nil, errors.New("Telegram config has no default IPv4 route")
	}
	return out, nil
}

func publicIPv4(ip netip.Addr) bool {
	if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, prefix := range excludedIPv4Routes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

var excludedIPv4Routes = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func (b *backend) refreshLoop(storage certmagic.Storage, client *http.Client) {
	var previous routingFiles
	cacheCtx, cancel := context.WithTimeout(b.ctx, 10*time.Second)
	data, err := storage.Load(cacheCtx, routingCacheKey)
	cancel()
	if err == nil && len(data) > maxRoutingCache {
		err = errors.New("cached Telegram routes exceed the size limit")
	}
	if err == nil {
		if err = json.Unmarshal(data, &previous); err == nil {
			var routes *routingConfig
			routes, err = parseRouting(previous)
			if err == nil {
				b.publishRoutes(routes)
			}
		}
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) && b.ctx.Err() == nil {
		b.log.Warn("could not load cached Telegram routes", zap.Error(err))
	}
	persisted := b.routes.Load() != nil
	if !persisted {
		previous = routingFiles{}
	}
	for b.ctx.Err() == nil {
		files, err := fetchRouting(b.ctx, client)
		if err == nil && (b.routes.Load() == nil ||
			!bytes.Equal(previous.Config, files.Config) || !bytes.Equal(previous.Secret, files.Secret)) {
			var routes *routingConfig
			routes, err = parseRouting(files)
			if err == nil {
				b.publishRoutes(routes)
				previous = files
				persisted = false
				b.log.Info("Telegram MTProxy routes updated")
			}
		}
		if b.routes.Load() != nil && !persisted {
			data, _ := json.Marshal(previous)
			storeCtx, cancel := context.WithTimeout(b.ctx, 10*time.Second)
			storeErr := storage.Store(storeCtx, routingCacheKey, data)
			cancel()
			persisted = storeErr == nil
			err = errors.Join(err, storeErr)
		}
		if err != nil && b.ctx.Err() == nil {
			b.log.Warn("could not refresh Telegram MTProxy routes", zap.Error(err))
		}
		delay := 24 * time.Hour
		if err != nil {
			delay = time.Minute
		}
		timer := time.NewTimer(delay)
		select {
		case <-b.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func fetchRouting(ctx context.Context, client *http.Client) (routingFiles, error) {
	config, err := fetchFile(ctx, client, telegramConfigURL, maxRoutingFile)
	if err != nil {
		return routingFiles{}, err
	}
	secret, err := fetchFile(ctx, client, telegramSecretURL, 128)
	return routingFiles{Config: config, Secret: secret}, err
}

func fetchFile(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned HTTP %d", req.URL.Path, response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err == nil && int64(len(data)) > limit {
		return nil, fmt.Errorf("%s response is too large", req.URL.Path)
	}
	return data, err
}
