package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/gorilla/websocket"
	"github.com/love4taylor/caddy-tproxy/internal/config"
	"github.com/love4taylor/caddy-tproxy/internal/frame"
	"github.com/love4taylor/caddy-tproxy/internal/session"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
)

type stalledUploadBody struct {
	started chan struct{}
	done    <-chan struct{}
}

type uploadDrainProbe struct {
	io.ReadCloser
	started chan struct{}
}

func (b uploadDrainProbe) Close() error {
	close(b.started)
	return b.ReadCloser.Close()
}

type stalledDownlinkWriter struct {
	http.ResponseWriter
	started         chan struct{}
	deadlineChanged chan struct{}
	stop            <-chan struct{}
	tlsCloseNotify  bool
	mu              sync.Mutex
	lastDeadline    time.Time
}

func (w *stalledDownlinkWriter) Write([]byte) (int, error) {
	close(w.started)
	if w.waitForDeadline() && w.tlsCloseNotify {
		// Match crypto/tls, which arms a new deadline for the alert after
		// the response data write has timed out.
		_ = w.SetWriteDeadline(time.Now().Add(5 * time.Second))
		w.waitForDeadline()
	}
	return 0, context.DeadlineExceeded
}

func (w *stalledDownlinkWriter) waitForDeadline() bool {
	for {
		w.mu.Lock()
		expired := !w.lastDeadline.IsZero() && !time.Now().Before(w.lastDeadline)
		w.mu.Unlock()
		if expired {
			return true
		}
		select {
		case <-w.deadlineChanged:
		case <-w.stop:
			return false
		}
	}
}

func (w *stalledDownlinkWriter) SetWriteDeadline(deadline time.Time) error {
	w.mu.Lock()
	w.lastDeadline = deadline
	w.mu.Unlock()
	select {
	case w.deadlineChanged <- struct{}{}:
	default:
	}
	return nil
}

func TestClosingSessionInterruptsHTTPDownlink(t *testing.T) {
	for _, mode := range []config.CarrierMode{config.CarrierHTTPS, config.CarrierHTTPSLanes} {
		t.Run(string(mode), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			in, peer := net.Pipe()
			defer in.Close()
			defer peer.Close()
			deadline, _ := ctx.Deadline()
			if err := peer.SetWriteDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			cfg := config.Defaults()
			cfg.PublicHostname = "proxy.example.test"
			profile := config.Profile{CarrierMode: mode, DialBackend: func(_ context.Context, ready func(error)) (net.Conn, error) {
				ready(nil)
				return in, nil
			}}
			cfg.Profiles = []config.Profile{profile}
			const address = "192.0.2.4"
			relay, err := NewEmbedded(cfg, [32]byte{1}, func(*http.Request) (string, error) { return address, nil })
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(relay.Shutdown)
			ticket, err := relay.manager.IssueBootstrap(&profile, address)
			if err != nil {
				t.Fatal(err)
			}
			created, err := relay.manager.Create(ticket, address, frame.Encode(frame.Hello, 0, []byte{1}))
			if err != nil {
				t.Fatal(err)
			}
			const id = 17
			open := frame.Encode(frame.Open, id, nil)
			if mode == config.CarrierHTTPSLanes {
				_, err = created.Session.ProcessUpLane(id, 1, open)
			} else {
				_, err = created.Session.ProcessUp(1, open)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := peer.Write([]byte("downlink data")); err != nil {
				t.Fatal(err)
			}
			if err := peer.Close(); err != nil {
				t.Fatal(err)
			}
			// Let the backend release its own read reservation before checking
			// the budget independently owned by the HTTP writer.
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			for relay.Capacity().Streams != 0 {
				select {
				case <-tick.C:
				case <-ctx.Done():
					t.Fatal("backend did not finish queuing the downlink")
				}
			}
			r := httptest.NewRequestWithContext(ctx, http.MethodPost, "https://"+cfg.PublicHostname+"/api/v1/down", nil)
			r.Header.Set("Authorization", "Bearer "+created.Token)
			r.Header.Set("X-Down-Cursor", "0")
			blocked := &stalledDownlinkWriter{
				ResponseWriter:  httptest.NewRecorder(),
				started:         make(chan struct{}),
				deadlineChanged: make(chan struct{}, 1),
				stop:            ctx.Done(),
				tlsCloseNotify:  mode == config.CarrierHTTPSLanes,
			}
			var writer http.ResponseWriter = blocked
			var restoreIdle func()
			if mode == config.CarrierHTTPSLanes {
				r.Header.Set("X-Lane-ID", strconv.Itoa(id))
				idle := &caddyhttp.IdleTimeoutWriter{
					ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: blocked},
					Ctrl:                  http.NewResponseController(blocked),
					Deadline:              caddyhttp.IdleDeadline{Start: time.Now(), Timeout: 30 * time.Second},
					Logger:                zap.NewNop(),
					ClearBetweenWrites:    true,
				}
				restoreIdle = idle.Override(10*time.Second, 0, 0)
				writer = idle
				r = r.WithContext(caddyhttp.ContextWithIdleTimeouts(r.Context(), nil, idle))
			}
			returned := make(chan struct{})
			go func() {
				defer close(returned)
				relay.ServeClaimed(writer, r)
			}()
			defer func() { cancel(); <-returned }()
			select {
			case <-blocked.started:
			case <-ctx.Done():
				t.Fatal("HTTP downlink did not start writing")
			}
			if relay.Capacity().PendingBytes == 0 {
				t.Fatal("the active writer lost its buffer charge")
			}
			remove := httptest.NewRequest(http.MethodDelete, "https://"+cfg.PublicHostname+"/api/v1/session", nil)
			remove.Header.Set("Authorization", "Bearer "+created.Token)
			response := httptest.NewRecorder()
			relay.ServeClaimed(response, remove)
			if response.Code != http.StatusNoContent {
				t.Fatalf("session deletion returned %d", response.Code)
			}
			select {
			case <-returned:
			case <-time.After(time.Second):
				t.Fatal("session deletion did not interrupt the blocked downlink")
			}
			if pending := relay.Capacity().PendingBytes; pending != 0 {
				t.Fatalf("downlink left %d bytes charged", pending)
			}
			if restoreIdle != nil {
				restoreIdle()
				if blocked.lastDeadline.IsZero() || time.Now().Before(blocked.lastDeadline) {
					t.Fatal("restoring the idle timeout reopened the expired write deadline")
				}
			}
		})
	}
}

func (b *stalledUploadBody) Read([]byte) (int, error) {
	close(b.started)
	<-b.done
	return 0, io.ErrUnexpectedEOF
}

func (*stalledUploadBody) Close() error { return nil }

func TestHTTPUploadAdmissionBeforeReadingBody(t *testing.T) {
	for _, mode := range []config.CarrierMode{config.CarrierHTTPS, config.CarrierHTTPSLanes} {
		t.Run(string(mode), func(t *testing.T) {
			cfg := config.Defaults()
			cfg.PublicHostname = "proxy.example.test"
			cfg.Limits.MaxStreamsPerSession = 2
			profile := config.Profile{Name: "test", CarrierMode: mode}
			cfg.Profiles = []config.Profile{profile}
			const address = "192.0.2.4"
			relay, err := NewEmbedded(cfg, [32]byte{1}, func(*http.Request) (string, error) { return address, nil })
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(relay.Shutdown)
			ticket, err := relay.manager.IssueBootstrap(&profile, address)
			if err != nil {
				t.Fatal(err)
			}
			created, err := relay.manager.Create(ticket, address, frame.Encode(frame.Hello, 0, []byte{1}))
			if err != nil {
				t.Fatal(err)
			}
			makeRequest := func(lane uint32) *http.Request {
				wire := frame.Encode(frame.Pong, 0, nil)
				if lane != 0 {
					wire = append(frame.Encode(frame.Open, lane, nil), frame.Encode(frame.Close, lane, nil)...)
				}
				r := httptest.NewRequest(http.MethodPost, "https://"+cfg.PublicHostname+"/api/v1/up", bytes.NewReader(wire))
				r.Header.Set("Authorization", "Bearer "+created.Token)
				r.Header.Set("Content-Type", binaryBody)
				r.Header.Set("X-Up-Seq", "1")
				if mode == config.CarrierHTTPSLanes {
					r.Header.Set("X-Lane-ID", strconv.FormatUint(uint64(lane), 10))
				}
				return r
			}
			serve := func(r *http.Request) *httptest.ResponseRecorder {
				out := httptest.NewRecorder()
				relay.ServeClaimed(out, r)
				return out
			}
			ctx, unblock := context.WithTimeout(t.Context(), 3*time.Second)
			defer unblock()
			var held int64
			var waiting []chan *httptest.ResponseRecorder
			stall := func(lane uint32) {
				r := makeRequest(lane)
				body := &stalledUploadBody{started: make(chan struct{}), done: ctx.Done()}
				r.Body = body
				result := make(chan *httptest.ResponseRecorder, 1)
				waiting = append(waiting, result)
				go func() { result <- serve(r) }()
				select {
				case <-body.started:
					held += r.ContentLength
				case <-ctx.Done():
					t.Fatalf("lane %d did not start reading", lane)
				}
			}
			checkRejected := func(lane uint32) {
				r := makeRequest(lane)
				body := &unreadableBody{}
				r.Body = body
				out := serve(r)
				if out.Code != http.StatusServiceUnavailable || out.Header().Get("Retry-After") != "1" || body.reads != 0 {
					t.Fatalf("lane %d: status=%d, reads=%d, Retry-After=%q", lane, out.Code, body.reads, out.Header().Get("Retry-After"))
				}
			}
			var lane uint32
			if mode == config.CarrierHTTPSLanes {
				lane = 1
			}
			stall(lane)
			checkRejected(lane)
			if mode == config.CarrierHTTPSLanes {
				stall(2)
				checkRejected(3)
				if out := serve(makeRequest(0)); out.Code != http.StatusNoContent {
					t.Fatalf("control lane was blocked by DATA lane readers: status %d", out.Code)
				}
			}
			if used := relay.Capacity().PendingBytes; used != held {
				t.Fatalf("body budget = %d, want %d", used, held)
			}
			unblock()
			for _, result := range waiting {
				select {
				case out := <-result:
					if out.Code != http.StatusNotFound {
						t.Fatalf("incomplete body returned status %d", out.Code)
					}
				case <-time.After(time.Second):
					t.Fatal("incomplete upload did not return")
				}
			}
			if used := relay.Capacity().PendingBytes; used != 0 {
				t.Fatalf("incomplete uploads left %d bytes charged", used)
			}
			for range 2 {
				if out := serve(makeRequest(lane)); out.Code != http.StatusNoContent || out.Header().Get("X-Up-Ack") != "1" {
					t.Fatalf("upload retry returned status %d and ACK %q", out.Code, out.Header().Get("X-Up-Ack"))
				}
			}
		})
	}
}

func TestClosingSessionInterruptsHTTPUpload(t *testing.T) {
	for _, tc := range []struct {
		proto string
		mode  config.CarrierMode
		drain bool
	}{
		{"HTTP/1.1", config.CarrierHTTPS, false},
		{"HTTP/1.1", config.CarrierHTTPS, true},
		{"HTTP/2.0", config.CarrierHTTPS, false},
		{"HTTP/3.0", config.CarrierHTTPS, false},
		{"HTTP/3.0", config.CarrierHTTPSLanes, false},
	} {
		name := tc.proto + "/" + string(tc.mode)
		if tc.drain {
			name += "/rejected-body"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			cfg := config.Defaults()
			cfg.PublicHostname = "proxy.example.test"
			profile := config.Profile{Name: "test", CarrierMode: tc.mode}
			cfg.Profiles = []config.Profile{profile}
			const address = "192.0.2.4"
			relay, err := NewEmbedded(cfg, [32]byte{1}, func(*http.Request) (string, error) { return address, nil })
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(relay.Shutdown)
			create := func() string {
				t.Helper()
				ticket, err := relay.manager.IssueBootstrap(&profile, address)
				if err != nil {
					t.Fatal(err)
				}
				created, err := relay.manager.Create(ticket, address, frame.Encode(frame.Hello, 0, []byte{1}))
				if err != nil {
					t.Fatal(err)
				}
				return created.Token
			}
			token := create()
			var held int
			var draining chan struct{}
			if tc.drain {
				// Leave less room than the request body. HTTP/1 still tries to
				// drain the unread bytes in Close when rejecting the upload.
				for relay.ChangeBufferBudget(32 << 10) {
					held += 32 << 10
				}
				defer relay.ChangeBufferBudget(-held)
				draining = make(chan struct{})
			}
			type uploadResult struct {
				protocol string
				pending  int64
			}
			returned := make(chan uploadResult, 1)
			listener := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if draining != nil && r.URL.Path == "/api/v1/up" {
					r.Body = uploadDrainProbe{ReadCloser: r.Body, started: draining}
				}
				relay.ServeClaimed(w, r)
				if r.URL.Path == "/api/v1/up" {
					returned <- uploadResult{r.Proto, relay.Capacity().PendingBytes}
				}
			}))
			listener.Config.ReadTimeout = 30 * time.Second
			listener.EnableHTTP2 = tc.proto == "HTTP/2.0"
			listener.StartTLS()
			t.Cleanup(listener.Close)
			client, base := listener.Client(), listener.URL
			var quicDials atomic.Int32
			if tc.proto == "HTTP/3.0" {
				client, base = startHTTP3UploadTest(t, listener, &quicDials)
			}
			request := func(method, path, token string, body io.Reader) *http.Request {
				t.Helper()
				r, err := http.NewRequestWithContext(ctx, method, base+"/api/v1/"+path, body)
				if err != nil {
					t.Fatal(err)
				}
				r.Host = cfg.PublicHostname
				r.Header.Set("Authorization", "Bearer "+token)
				if body != nil {
					r.Header.Set("Content-Type", binaryBody)
					r.Header.Set("X-Up-Seq", "1")
					if tc.mode == config.CarrierHTTPSLanes {
						r.Header.Set("X-Lane-ID", "0")
					}
				}
				return r
			}
			body, sender := io.Pipe()
			defer sender.Close()
			r := request(http.MethodPost, "up", token, body)
			r.ContentLength = 64 << 10
			if tc.mode == config.CarrierHTTPSLanes {
				r.Header.Set("X-Lane-ID", "9")
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer body.Close()
				if response, err := client.Do(r); err == nil {
					_ = response.Body.Close()
				}
			}()
			defer func() {
				cancel()
				_ = sender.Close()
				<-done
			}()
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			if draining != nil {
				select {
				case <-draining:
				case <-ctx.Done():
					t.Fatal("rejected HTTP upload did not start draining its body")
				}
			}
			for draining == nil && relay.Capacity().PendingBytes == 0 {
				select {
				case <-done:
					t.Fatal("HTTP upload ended before reserving its buffer")
				case <-ctx.Done():
					t.Fatal("HTTP upload did not reserve its buffer")
				case <-tick.C:
				}
			}
			removed, err := client.Do(request(http.MethodDelete, "session", token, nil))
			if err != nil {
				t.Fatal(err)
			}
			_ = removed.Body.Close()
			if removed.StatusCode != http.StatusNoContent || removed.Proto != tc.proto {
				t.Fatalf("session deletion returned %s over %s", removed.Status, removed.Proto)
			}
			select {
			case result := <-returned:
				if result.protocol != tc.proto || result.pending != int64(held) {
					t.Fatalf("upload ended over %s with %d bytes charged, want %s and %d", result.protocol, result.pending, tc.proto, held)
				}
			case <-time.After(time.Second):
				t.Fatal("session deletion did not interrupt the blocked upload")
			}
			if tc.proto == "HTTP/3.0" {
				pong := bytes.NewReader(frame.Encode(frame.Pong, 0, nil))
				next, err := client.Do(request(http.MethodPost, "up", create(), pong))
				if err != nil {
					t.Fatal(err)
				}
				_ = next.Body.Close()
				if ack := next.Header.Get("X-Up-Ack"); next.StatusCode != http.StatusNoContent || next.Proto != tc.proto ||
					ack != "1" || quicDials.Load() != 1 {
					t.Fatalf("next upload returned %s, ACK %q, with %d QUIC dials", next.Status, ack, quicDials.Load())
				}
			}
		})
	}
}

func startHTTP3UploadTest(t *testing.T, listener *httptest.Server, dials *atomic.Int32) (*http.Client, string) {
	t.Helper()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{TLSConfig: http3.ConfigureTLSConfig(listener.TLS), Handler: listener.Config.Handler}
	ended := make(chan error, 1)
	go func() { ended <- server.Serve(packet) }()
	transport := &http3.Transport{
		TLSClientConfig: listener.Client().Transport.(*http.Transport).TLSClientConfig.Clone(),
		Dial: func(ctx context.Context, address string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
			dials.Add(1)
			return quic.DialAddrEarly(ctx, address, tlsConfig, config)
		},
	}
	t.Cleanup(func() {
		_ = transport.Close()
		_ = server.Close()
		_ = packet.Close()
		if err := <-ended; err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			t.Errorf("HTTP/3 server stopped with %v", err)
		}
	})
	return &http.Client{Transport: transport}, "https://" + packet.LocalAddr().String()
}

func TestCarrierBodyChargesAllocationAndReleasesErrors(t *testing.T) {
	settings := config.Defaults()
	settings.Limits.MaxBodyBytes = 9000
	manager := session.NewManager(settings, [32]byte{1})
	t.Cleanup(manager.Shutdown)
	relay := Server{config: settings, manager: manager}
	payload := bytes.Repeat([]byte{0x1d}, 7101)
	for _, length := range []int64{int64(len(payload)), -1} {
		body, err := relay.readBatch(bytes.NewReader(payload), length)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(body.Bytes, payload) || manager.Capacity().PendingBytes != int64(cap(body.Bytes)) {
			t.Fatal("assembled body differs or its backing allocation is undercharged")
		}
		body.release()
		if used := manager.Capacity().PendingBytes; used != 0 {
			t.Fatalf("releasing body left %d bytes charged", used)
		}
	}
	for _, tc := range []struct {
		length int64
		size   int
		want   error
	}{
		{8000, 7101, io.ErrUnexpectedEOF},
		{7100, 7101, errCarrierBody},
		{-1, 9001, errCarrierBody},
	} {
		body, err := relay.readBatch(bytes.NewReader(make([]byte, tc.size)), tc.length)
		if !errors.Is(err, tc.want) || body.Bytes != nil {
			t.Errorf("size=%d, content-length=%d: got %v, want %v", tc.size, tc.length, err, tc.want)
		}
		if used := manager.Capacity().PendingBytes; used != 0 {
			t.Fatalf("rejected body leaked %d bytes of budget", used)
		}
	}
}

func TestCarrierBodyRejectsPrematureTransportEOF(t *testing.T) {
	settings := config.Defaults()
	manager := session.NewManager(settings, [32]byte{1})
	t.Cleanup(manager.Shutdown)
	relay := Server{config: settings, manager: manager}
	for _, size := range []int{10, frame.InitialBatchBufferBytes, frame.InitialBatchBufferBytes + 1, frame.InitialBatchBufferBytes + 37} {
		for _, expected := range []int64{-1, int64(size)} {
			payload := bytes.Repeat([]byte{1}, size)
			clean, err := relay.readBatch(iotest.DataErrReader(bytes.NewReader(payload)), expected)
			if err != nil || !bytes.Equal(clean.Bytes, payload) {
				t.Fatalf("size %d, content length %d: clean EOF returned %v", size, expected, err)
			}
			clean.release()
			reader := iotest.DataErrReader(io.MultiReader(bytes.NewReader(payload), iotest.ErrReader(io.ErrUnexpectedEOF)))
			body, err := relay.readBatch(reader, expected)
			if body.Bytes != nil {
				body.release()
				t.Errorf("size %d, content length %d: returned a truncated body", size, expected)
			}
			if err != io.ErrUnexpectedEOF || manager.Capacity().PendingBytes != 0 {
				t.Errorf("size %d, content length %d: got %v with %d bytes charged", size, expected, err, manager.Capacity().PendingBytes)
			}
		}
	}
}

func TestInterruptedChunkedUploadDoesNotCommitFrames(t *testing.T) {
	for _, mode := range []config.CarrierMode{config.CarrierHTTPS, config.CarrierHTTPSLanes} {
		t.Run(string(mode), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			cfg := config.Defaults()
			cfg.PublicHostname = "proxy.example.test"
			peer := make(chan net.Conn, 1)
			profile := config.Profile{Name: "test", CarrierMode: mode, DialBackend: func(ctx context.Context, ready func(error)) (net.Conn, error) {
				local, remote := net.Pipe()
				select {
				case peer <- remote:
					ready(nil)
					return local, nil
				case <-ctx.Done():
					_ = local.Close()
					_ = remote.Close()
					return nil, ctx.Err()
				}
			}}
			cfg.Profiles = []config.Profile{profile}
			const address = "192.0.2.4"
			relay, err := NewEmbedded(cfg, [32]byte{1}, func(*http.Request) (string, error) { return address, nil })
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(relay.Shutdown)
			ticket, err := relay.manager.IssueBootstrap(&profile, address)
			if err != nil {
				t.Fatal(err)
			}
			created, err := relay.manager.Create(ticket, address, frame.Encode(frame.Hello, 0, []byte{1}))
			if err != nil {
				t.Fatal(err)
			}
			finished := make(chan struct{}, 3)
			host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				relay.ServeClaimed(w, r)
				finished <- struct{}{}
			}))
			defer host.Close()
			const id = 17
			uplink := func(payload []byte) []byte {
				return append(frame.Encode(frame.Open, id, nil), frame.Encode(frame.Data, id, payload)...)
			}
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", host.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			var laneHeader string
			if mode == config.CarrierHTTPSLanes {
				laneHeader = "X-Lane-ID: 17\r\n"
			}
			prefix := uplink([]byte("complete WEB frames in an incomplete HTTP body"))
			if _, err := fmt.Fprintf(conn, "POST /api/v1/up HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nAuthorization: Bearer %s\r\nContent-Type: %s\r\nX-Up-Seq: 1\r\n%sTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n", cfg.PublicHostname, created.Token, binaryBody, laneHeader, len(prefix), prefix); err != nil {
				t.Fatal(err)
			}
			// Drop the request before its required zero-length final chunk.
			if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-finished:
			case <-ctx.Done():
				t.Fatal("handler did not finish the interrupted request")
			}
			if usage := relay.Capacity(); usage.Streams != 0 || usage.PendingBytes != 0 || relay.Metrics().BytesUp != 0 {
				t.Fatalf("interrupted HTTP body committed frames: %+v", usage)
			}

			payload := []byte("only the complete retry reaches the backend")
			wire := uplink(payload)
			for range 2 {
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, host.URL+"/api/v1/up", bytes.NewReader(wire))
				if err != nil {
					t.Fatal(err)
				}
				req.Host = cfg.PublicHostname
				req.Header.Set("Authorization", "Bearer "+created.Token)
				req.Header.Set("Content-Type", binaryBody)
				req.Header.Set("X-Up-Seq", "1")
				if laneHeader != "" {
					req.Header.Set("X-Lane-ID", "17")
				}
				res, err := host.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_ = res.Body.Close()
				if res.StatusCode != http.StatusNoContent || res.Header.Get("X-Up-Ack") != "1" {
					t.Fatalf("retry returned %d and ACK %q", res.StatusCode, res.Header.Get("X-Up-Ack"))
				}
			}
			select {
			case upstream := <-peer:
				defer upstream.Close()
				if err := upstream.SetReadDeadline(deadline); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(upstream, got); err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("backend got %q: %v", got, err)
				}
			case <-ctx.Done():
				t.Fatal("retry did not establish a backend stream")
			}
			if used := relay.Metrics().BytesUp; used != uint64(len(wire)) {
				t.Fatalf("retries committed %d bytes, want %d", used, len(wire))
			}
		})
	}
}

func TestCarrierBodyCacheDoesNotExposeOrOverwriteAnotherBody(t *testing.T) {
	settings := config.Defaults()
	manager := session.NewManager(settings, [32]byte{1})
	t.Cleanup(manager.Shutdown)
	relay := Server{config: settings, manager: manager}
	media := bytes.Repeat([]byte{0xd7}, (64<<10)+8)
	first, err := relay.readBatch(bytes.NewReader(media), int64(len(media)))
	if err != nil {
		t.Fatal(err)
	}
	defer first.release()
	short := bytes.Repeat([]byte{0x21}, (64<<10)+1)
	for i := range 2 {
		second, err := relay.readBatch(bytes.NewReader(short), int64(len(short)))
		if err != nil {
			t.Fatal(err)
		}
		same := bytes.Equal(second.Bytes, short) && bytes.Equal(first.Bytes, media)
		chunkCapacity := manager.Capacity().PendingBytes
		want := int64(cap(first.Bytes) + cap(second.Bytes))
		second.release()
		if !same || chunkCapacity != want {
			t.Fatalf("read %d: pooled reads failed to preserve data and charge backing capacity", i)
		}
	}
}

func TestCarrierBodyGrowthReleasesReservationOnBudgetExhaustion(t *testing.T) {
	settings := config.Defaults()
	settings.Limits.MaxSessionsGlobal = 1
	settings.Limits.MaxStreamsPerSession = 1
	settings.Limits.MaxPendingGlobal = 128 << 10
	manager := session.NewManager(settings, [32]byte{1})
	t.Cleanup(manager.Shutdown)
	relay := Server{config: settings, manager: manager}
	body, err := relay.readBatch(bytes.NewReader(make([]byte, 70<<10)), -1)
	if !errors.Is(err, session.ErrBackpressure) || body.Bytes != nil {
		t.Fatalf("got carrier body error %v, want backpressure", err)
	}
	if used := manager.Capacity().PendingBytes; used != 0 {
		t.Fatalf("failed growth leaked %d bytes of budget", used)
	}
}

type observedBackend struct {
	net.Conn
	reads chan struct{}
}

func (c *observedBackend) Read(data []byte) (int, error) {
	select {
	case c.reads <- struct{}{}:
	default:
	}
	return c.Conn.Read(data)
}

func TestWebSocketDownlinkKeepsOneMessageAtBudgetLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	in, peer := net.Pipe()
	defer in.Close()
	defer peer.Close()
	observed := &observedBackend{Conn: in, reads: make(chan struct{}, 3)}
	cfg := config.Defaults()
	cfg.PublicHostname = "proxy.example.test"
	cfg.Limits.MaxPendingGlobal = 4 << 20
	cfg.Limits.MaxPendingPerSession = 4 << 20
	cfg.Limits.MaxSessionsGlobal = 1
	profile := config.Profile{CarrierMode: config.CarrierWebSocket, DialBackend: func(_ context.Context, ready func(error)) (net.Conn, error) {
		ready(nil)
		return observed, nil
	}}
	cfg.Profiles = []config.Profile{profile}
	const address = "192.0.2.4"
	relay, err := NewEmbedded(cfg, [32]byte{1}, func(*http.Request) (string, error) { return address, nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(relay.Shutdown)
	ticket, err := relay.manager.IssueBootstrap(&profile, address)
	if err != nil {
		t.Fatal(err)
	}
	created, err := relay.manager.Create(ticket, address, frame.Encode(frame.Hello, 0, []byte{1}))
	if err != nil {
		t.Fatal(err)
	}
	const id = 17
	if _, err := created.Session.ProcessWebSocket(ctx, 0, 1, frame.Encode(frame.Open, id, nil)); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetWriteDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	var want []byte
	for _, value := range []byte{7, 19} {
		data := bytes.Repeat([]byte{value}, frame.DataChunk)
		if _, err := peer.Write(data); err != nil {
			t.Fatal(err)
		}
		want = append(want, frame.Encode(frame.Data, id, data)...)
	}
	// Starting the third read confirms both DATA frames are queued.
	for range cap(observed.reads) {
		select {
		case <-observed.reads:
		case <-ctx.Done():
			t.Fatal("the backend did not finish queuing DATA")
		}
	}
	var held int
	for relay.ChangeBufferBudget(frame.DataChunk) {
		held += frame.DataChunk
	}
	defer relay.ChangeBufferBudget(-held)
	server := httptest.NewServer(http.HandlerFunc(relay.ServeClaimed))
	defer server.Close()
	dialer := websocket.Dialer{Subprotocols: []string{webSocketProtocolPrefix + created.Token}}
	client, _, err := dialer.DialContext(ctx, "ws"+server.URL[len("http"):]+"/api/v1/ws", http.Header{"Host": {cfg.PublicHostname}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	kind, payload, err := client.ReadMessage()
	if err != nil || kind != websocket.BinaryMessage || !bytes.Equal(payload, want) {
		t.Fatalf("got a message of type %d and %d bytes, want %d bytes: %v", kind, len(payload), len(want), err)
	}
}

type blockedSocketWriter struct {
	net.Conn
	armed, writing, closed chan struct{}
	closeOnce              sync.Once
	stop                   <-chan struct{}
}

func (c *blockedSocketWriter) Write(data []byte) (int, error) {
	select {
	case <-c.armed:
		close(c.writing)
		select {
		case <-c.closed:
			return 0, net.ErrClosed
		case <-c.stop:
			return 0, context.DeadlineExceeded
		}
	default:
		return c.Conn.Write(data)
	}
}

func (c *blockedSocketWriter) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

type socketTestResponse struct {
	http.ResponseWriter
	conn *blockedSocketWriter
}

func (w socketTestResponse) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	w.conn.Conn = conn
	return w.conn, rw, nil
}

func TestRejectedWebSocketHandshakeReleasesReservation(t *testing.T) {
	cfg := config.Defaults()
	cfg.PublicHostname = "proxy.example.test"
	profile := config.Profile{CarrierMode: config.CarrierWebSocket}
	cfg.Profiles = []config.Profile{profile}
	const address = "192.0.2.4"
	relay, err := NewEmbedded(cfg, [32]byte{1}, func(*http.Request) (string, error) { return address, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Shutdown()
	ticket, err := relay.manager.IssueBootstrap(&profile, address)
	if err != nil {
		t.Fatal(err)
	}
	created, err := relay.manager.Create(ticket, address, frame.Encode(frame.Hello, 0, []byte{1}))
	if err != nil {
		t.Fatal(err)
	}
	protocol := webSocketProtocolPrefix + created.Token
	request := httptest.NewRequest(http.MethodGet, "https://"+cfg.PublicHostname+"/api/v1/ws", nil)
	request.Header.Set("Sec-WebSocket-Protocol", protocol)
	response := httptest.NewRecorder()
	relay.ServeClaimed(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("incomplete handshake returned HTTP %d", response.Code)
	}
	returned := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(returned)
		relay.ServeClaimed(w, r)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	dialer := websocket.Dialer{Subprotocols: []string{protocol}}
	client, _, err := dialer.DialContext(ctx, "ws"+server.URL[len("http"):]+"/api/v1/ws", http.Header{"Host": {cfg.PublicHostname}})
	if err != nil {
		t.Fatalf("valid retry with the same session failed: %v", err)
	}
	_ = client.Close()
	select {
	case <-returned:
	case <-ctx.Done():
		t.Fatal("WebSocket handler did not exit")
	}
	if created.Session.ClaimWebSocket(0) {
		t.Fatal("closing an established multiplexed socket left the session open")
	}
}

func TestClosingSessionInterruptsWebSocketHandshake(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	cfg := config.Defaults()
	cfg.PublicHostname = "proxy.example.test"
	profile := config.Profile{CarrierMode: config.CarrierWebSocketLanes}
	cfg.Profiles = []config.Profile{profile}
	const address = "192.0.2.4"
	relay, err := NewEmbedded(cfg, [32]byte{1}, func(*http.Request) (string, error) { return address, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Shutdown()
	ticket, err := relay.manager.IssueBootstrap(&profile, address)
	if err != nil {
		t.Fatal(err)
	}
	created, err := relay.manager.Create(ticket, address, frame.Encode(frame.Hello, 0, []byte{1}))
	if err != nil {
		t.Fatal(err)
	}
	conn := &blockedSocketWriter{armed: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{}), stop: ctx.Done()}
	close(conn.armed)
	returned := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(returned)
		relay.ServeClaimed(socketTestResponse{ResponseWriter: w, conn: conn}, r)
	}))
	defer server.Close()
	finished := make(chan error, 1)
	go func() {
		dialer := websocket.Dialer{Subprotocols: []string{webSocketLaneProtocolPrefix + created.Token + ".17"}}
		client, _, err := dialer.DialContext(ctx, "ws"+server.URL[len("http"):]+"/api/v1/ws", http.Header{"Host": {cfg.PublicHostname}})
		if client != nil {
			_ = client.Close()
		}
		finished <- err
	}()
	select {
	case <-conn.writing:
	case <-ctx.Done():
		t.Fatal("handshake did not start writing its response")
	}
	created.Session.Close()
	select {
	case <-returned:
	case <-ctx.Done():
		t.Fatal("session close did not interrupt the handshake write")
	}
	if err := <-finished; err == nil {
		t.Fatal("client upgraded after session closed")
	}
}

func TestClosingSessionInterruptsWebSocketDownlink(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	in, peer := net.Pipe()
	defer in.Close()
	defer peer.Close()
	deadline, _ := ctx.Deadline()
	if err := peer.SetWriteDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.PublicHostname = "proxy.example.test"
	profile := config.Profile{CarrierMode: config.CarrierWebSocketLanes, DialBackend: func(_ context.Context, ready func(error)) (net.Conn, error) {
		ready(nil)
		return in, nil
	}}
	cfg.Profiles = []config.Profile{profile}
	const address = "192.0.2.4"
	relay, err := NewEmbedded(cfg, [32]byte{1}, func(*http.Request) (string, error) { return address, nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(relay.Shutdown)
	ticket, err := relay.manager.IssueBootstrap(&profile, address)
	if err != nil {
		t.Fatal(err)
	}
	created, err := relay.manager.Create(ticket, address, frame.Encode(frame.Hello, 0, []byte{1}))
	if err != nil {
		t.Fatal(err)
	}
	conn := &blockedSocketWriter{armed: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{}), stop: ctx.Done()}
	returned := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(returned)
		relay.ServeClaimed(socketTestResponse{ResponseWriter: w, conn: conn}, r)
	}))
	defer server.Close()
	const id = 17
	protocol := webSocketLaneProtocolPrefix + created.Token + "." + strconv.Itoa(id)
	dialer := websocket.Dialer{Subprotocols: []string{protocol}}
	client, _, err := dialer.DialContext(ctx, "ws"+server.URL[len("http"):]+"/api/v1/ws", http.Header{"Host": {cfg.PublicHostname}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	close(conn.armed)
	if err := client.WriteMessage(websocket.BinaryMessage, frame.Encode(frame.Open, id, nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write([]byte("downlink data")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-conn.writing:
	case <-ctx.Done():
		t.Fatal("WebSocket did not start writing the downlink batch")
	}
	if relay.Capacity().PendingBytes == 0 {
		t.Fatal("the active writer lost its buffer charge")
	}
	request := httptest.NewRequest(http.MethodDelete, "https://"+cfg.PublicHostname+"/api/v1/session", nil)
	request.Header.Set("Authorization", "Bearer "+created.Token)
	response := httptest.NewRecorder()
	relay.ServeClaimed(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("session deletion returned %d", response.Code)
	}
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("session deletion did not interrupt the blocked WebSocket")
	}
	relay.Shutdown()
	if capacity := relay.Capacity(); capacity != (session.Capacity{}) {
		t.Fatalf("retired session retained resources: %+v", capacity)
	}
}
