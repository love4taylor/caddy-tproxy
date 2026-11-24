package tproxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/gorilla/websocket"
	"github.com/love4taylor/caddy-tproxy/internal/config"
	"github.com/love4taylor/caddy-tproxy/internal/frame"
	"github.com/love4taylor/caddy-tproxy/internal/server"
	"go.uber.org/zap"
)

func TestEarlyDataRejectedByEmbeddedHandler(t *testing.T) {
	value := config.Defaults()
	value.PublicHostname = "proxy.example.test"
	capability := [32]byte{42}
	value.Profiles = []config.Profile{{Capability: capability}}
	relay, err := server.NewEmbedded(value, [32]byte{7}, clientIP)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(relay.Shutdown)
	module := &Handler{hosts: map[string]*hostRelay{value.PublicHostname: {relay: relay}}}
	fallback := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusAccepted)
		return nil
	})
	for _, path := range []struct {
		name   string
		target string
		status int
	}{
		{"relay", "/?bridge=" + config.CapabilityString(capability), http.StatusTooEarly},
		{"public", "/", http.StatusAccepted},
	} {
		t.Run(path.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://"+value.PublicHostname+path.target, nil)
			r.TLS.HandshakeComplete = true
			r.Header["Early-Data"] = []string{"", "1"}
			w := httptest.NewRecorder()
			if err := module.ServeHTTP(w, r, fallback); err != nil || w.Code != path.status {
				t.Fatalf("got HTTP %d, error %v", w.Code, err)
			}
			if path.status == http.StatusTooEarly && w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("early-data response can be cached")
			}
		})
	}
}

func TestEmbeddedCarriersMediaRoundTrip(t *testing.T) {
	const hostname = "proxy.example.test"
	const streamID = 17
	const packetsPerBatch = 16
	const batches = 8
	const packetSize = 64 << 10
	modes := []config.CarrierMode{
		config.CarrierHTTPS, config.CarrierHTTPSLanes,
		config.CarrierWebSocket, config.CarrierWebSocketLanes,
	}
	for _, mode := range modes {
		t.Run(string(mode), func(t *testing.T) {
			listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			deadline := time.Now().Add(15 * time.Second)
			if err := listener.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			b := &backend{ctx: ctx, cancel: cancel, log: zap.NewNop(), warmSignal: make(chan struct{}, 1)}
			defer b.close()
			routes := &routingConfig{
				dcs:    map[int16][]netip.AddrPort{2: {listener.Addr().(*net.TCPAddr).AddrPort()}},
				secret: [128]byte{24, 79, 87, 12},
			}
			b.routes.Store(routes)
			secret := [16]byte{44}
			replays := new(handshakeReplays)
			value := config.Defaults()
			value.PublicHostname = hostname
			capability := config.DeriveCapability(hostname, "", secret[:])
			value.Profiles = []config.Profile{{
				Name: "test", CarrierMode: mode, Capability: capability,
				DialBackend: func(ctx context.Context, ready func(error)) (net.Conn, error) {
					return b.dial(ctx, secret, replays, ready)
				},
			}}
			relay, err := server.NewEmbedded(value, [32]byte{7}, clientIP)
			if err != nil {
				t.Fatal(err)
			}
			defer relay.Shutdown()
			b.buffer.shared = relay.ChangeBufferBudget
			b.wg.Go(b.maintainMiddle)

			fixture := make(chan error, 1)
			go func() {
				conn, err := listener.AcceptTCP()
				if err != nil {
					fixture <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(deadline)
				fixture <- echoMiddleMedia(conn, routes.secret, packetsPerBatch*batches)
				<-ctx.Done()
			}()
			for b.stats.sockets.Load() == 0 {
				if time.Now().After(deadline) {
					t.Fatal("background pool did not establish a ready socket")
				}
				time.Sleep(time.Millisecond)
			}

			module := &Handler{hosts: map[string]*hostRelay{hostname: {relay: relay}}}
			fallback := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				http.NotFound(w, r)
				return nil
			})
			host := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = module.ServeHTTP(w, r, fallback)
			}))
			host.EnableHTTP2 = true
			host.StartTLS()
			defer host.Close()
			host.Client().Timeout = 5 * time.Second
			request := func(method, path, token string, body []byte, headers http.Header, status int) ([]byte, http.Header) {
				t.Helper()
				req, err := http.NewRequestWithContext(t.Context(), method, host.URL+path, bytes.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				req.Host = hostname
				if token != "" {
					req.Header.Set("Authorization", "Bearer "+token)
					req.Header.Set("Origin", "https://"+hostname)
				}
				if body != nil {
					req.Header.Set("Content-Type", "application/octet-stream")
				}
				for key, values := range headers {
					req.Header[key] = values
				}
				resp, err := host.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != status {
					t.Fatalf("%s %s returned %d, want %d", method, path, resp.StatusCode, status)
				}
				data, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				return data, resp.Header
			}
			page, _ := request("GET", "/?bridge="+config.CapabilityString(capability), "", nil, nil, 200)
			_, bootstrap, found := strings.Cut(string(page), `bootstrap="`)
			if !found || len(bootstrap) < 43 {
				t.Fatal("bridge did not issue bootstrap")
			}
			_, headers := request("POST", "/api/v1/session", bootstrap[:43], frame.Encode(frame.Hello, 0, []byte{1}), nil, 200)
			token := headers.Get("X-Session-Token")
			if headers.Get("X-Carrier-Mode") != string(mode) || token == "" {
				t.Fatal("wrong carrier negotiated")
			}

			var wire bytes.Buffer
			client, err := dialObfuscatedFixture(&wire, intermediate, 2, secret[:])
			if err != nil {
				t.Fatal(err)
			}
			var send func([]byte, int)
			var receive func() []byte
			switch mode {
			case config.CarrierHTTPS, config.CarrierHTTPSLanes:
				laneHeader := http.Header{}
				if mode == config.CarrierHTTPSLanes {
					laneHeader.Set("X-Lane-ID", "17")
				}
				up := laneHeader.Clone()
				send = func(body []byte, sequence int) {
					up.Set("X-Up-Seq", fmt.Sprint(sequence))
					request("POST", "/api/v1/up", token, body, up, 204)
				}
				laneHeader.Set("X-Down-Cursor", "0")
				receive = func() []byte {
					body, down := request("POST", "/api/v1/down", token, nil, laneHeader, 200)
					laneHeader.Set("X-Down-Cursor", down.Get("X-Down-Cursor"))
					return body
				}
			case config.CarrierWebSocket, config.CarrierWebSocketLanes:
				protocol := "tproxy-v1." + token
				if mode == config.CarrierWebSocketLanes {
					protocol = "tproxy-lane-v1." + token + ".17"
				}
				tls := host.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
				tls.NextProtos = []string{"http/1.1"}
				dialer := websocket.Dialer{TLSClientConfig: tls, Subprotocols: []string{protocol}, HandshakeTimeout: 5 * time.Second}
				conn, _, err := dialer.DialContext(t.Context(), "wss"+strings.TrimPrefix(host.URL, "https")+"/api/v1/ws",
					http.Header{"Host": {hostname}, "Origin": {"https://" + hostname}})
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				if err := conn.SetReadDeadline(deadline); err != nil {
					t.Fatal(err)
				}
				if err := conn.SetWriteDeadline(deadline); err != nil {
					t.Fatal(err)
				}
				send = func(body []byte, _ int) {
					if err := conn.WriteMessage(websocket.BinaryMessage, body); err != nil {
						t.Fatal(err)
					}
				}
				receive = func() []byte {
					kind, body, err := conn.ReadMessage()
					if err != nil {
						t.Fatal(err)
					}
					if kind != websocket.BinaryMessage {
						t.Fatalf("expected binary message, got %d", kind)
					}
					return body
				}
			}

			payload := make([]byte, packetSize)
			source := rand.NewChaCha8([32]byte{29, 47, 71, 92})
			expected := rand.NewChaCha8([32]byte{29, 47, 71, 92})
			const responseSize = packetsPerBatch * (packetSize + 4)
			const uploadCapacity = responseSize + frame.HeaderSize*(packetsPerBatch+2) + 64 + 4
			upload := make([]byte, 0, uploadCapacity)
			start := time.Now()
			for batch := range batches {
				upload = upload[:0]
				if batch == 0 {
					upload = append(upload, frame.Encode(frame.Open, streamID, nil)...)
				} else {
					upload = append(upload, frame.Encode(frame.Window, streamID, frame.WindowPayload(responseSize))...)
				}
				var upBytes uint32
				for range packetsPerBatch {
					_, _ = source.Read(payload)
					if err := client.writer.writePacket(intermediate, payload); err != nil {
						t.Fatal(err)
					}
					upBytes += uint32(wire.Len())
					upload = append(upload, frame.Encode(frame.Data, streamID, wire.Bytes())...)
					wire.Reset()
				}
				send(upload, batch+1)
				var upCredit uint32
				for wire.Len() < responseSize || upCredit < upBytes {
					frames, err := frame.ParseAll(receive(), frame.MaxPayload)
					if err != nil {
						t.Fatal(err)
					}
					for _, f := range frames {
						if f.StreamID != streamID {
							t.Fatalf("unexpected downlink stream %d", f.StreamID)
						}
						switch f.Type {
						case frame.Data:
							wire.Write(f.Payload)
						case frame.Window:
							amount, err := frame.WindowAmount(f.Payload)
							if err != nil || amount > upBytes-upCredit {
								t.Fatalf("invalid uplink credit %d after %d of %d bytes", amount, upCredit, upBytes)
							}
							upCredit += amount
						default:
							t.Fatalf("unexpected downlink frame type %d", f.Type)
						}
					}
				}
				for i := range packetsPerBatch {
					_, _ = expected.Read(payload)
					body, _, err := readTransportPacket(client.reader, intermediate)
					if err != nil || !bytes.Equal(body, payload) {
						t.Fatalf("invalid echoed packet %d, length %d, error %v", batch*packetsPerBatch+i, len(body), err)
					}
				}
				if wire.Len() != 0 {
					t.Fatal("unexpected extra downlink bytes")
				}
			}
			elapsed := time.Since(start)
			if err := <-fixture; err != nil {
				t.Fatal(err)
			}
			t.Logf("%d MiB up + %d MiB down: %s", batches, batches, elapsed)
		})
	}
}

func echoMiddleMedia(conn *net.TCPConn, secret [128]byte, count int) error {
	peer, err := negotiateMiddleFixture(conn, secret)
	if err != nil {
		return err
	}
	for range count {
		packet, err := peer.read(maxRPCPacket)
		if err != nil {
			return err
		}
		if len(packet) != 56+(64<<10) || le.Uint32(packet) != rpcProxyReq {
			return fmt.Errorf("unexpected RPC request length %d", len(packet))
		}
		if err := writeMiddleAnswer(peer, le.Uint64(packet[8:]), packet[56:]); err != nil {
			return err
		}
	}
	return nil
}
