package tproxy

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func TestRoutingConfig(t *testing.T) {
	files := routingFiles{
		Config: []byte("# test\ndefault 2;\nproxy_for 2 8.8.8.8:8888;\nproxy_for -2 1.1.1.1:8888;\nproxy_for -2 [2001:db8::21]:8888;\nproxy_for 203 9.9.9.9:443;\n"),
		Secret: make([]byte, 128),
	}
	routes, err := parseRouting(files)
	if err != nil {
		t.Fatal(err)
	}
	if got := routes.targets(-2); len(got) != 1 || got[0].String() != "1.1.1.1:8888" {
		t.Fatalf("media DC routes = %v", got)
	}
	if got := routes.targets(9); len(got) != 1 || got[0].String() != "8.8.8.8:8888" {
		t.Fatalf("fallback routes = %v", got)
	}
	if got := routes.targets(203); len(got) != 1 || got[0].String() != "9.9.9.9:443" {
		t.Fatalf("CDN routes = %v", got)
	}
	files.Secret = files.Secret[:127]
	if _, err := parseRouting(files); err == nil {
		t.Fatal("accepted a truncated Telegram key")
	}
}

func TestRoutingTrustBoundary(t *testing.T) {
	for _, target := range []string{
		"10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1", "192.0.2.1", "198.18.0.1", "240.0.0.1",
	} {
		files := routingFiles{
			Config: []byte("default 2;\nproxy_for 2 " + target + ":8888;\n"),
			Secret: make([]byte, 128),
		}
		if _, err := parseRouting(files); err == nil {
			t.Errorf("accepted non-public address %s", target)
		}
	}
	for _, url := range []string{"http://core.telegram.org/", "https://example.com/"} {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkRoutingRedirect(req, nil); err == nil {
			t.Errorf("accepted routing redirect to %s", url)
		}
	}
	req, err := http.NewRequest(http.MethodGet, telegramConfigURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkRoutingRedirect(req, nil); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshStoresValidatedTelegramFiles(t *testing.T) {
	files := routingFiles{
		Config: []byte("default 2;\nproxy_for 2 1.1.1.1:8888;\n"),
		Secret: bytes.Repeat([]byte{42}, 128),
	}
	storage := &certmagic.FileStorage{Path: t.TempDir()}
	ctx, cancel := context.WithCancel(t.Context())
	b := &backend{ctx: ctx, cancel: cancel, log: zap.NewNop(), routesReady: make(chan struct{})}
	t.Cleanup(b.close)
	b.wg.Go(func() {
		b.refreshLoop(storage, &http.Client{Transport: routingFixture(files)})
	})
	select {
	case <-b.routesReady:
	case <-time.After(4 * time.Second):
		t.Fatal("Telegram route refresh did not finish")
	}
	if b.routes.Load() == nil {
		t.Fatal("no routes published")
	}
	deadline := time.Now().Add(4 * time.Second)
	for {
		raw, err := storage.Load(ctx, routingCacheKey)
		if err == nil {
			var stored routingFiles
			if err := json.Unmarshal(raw, &stored); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(stored.Config, files.Config) || !bytes.Equal(stored.Secret, files.Secret) {
				t.Fatal("wrong Telegram files cached")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRefreshIgnoresOversizedCache(t *testing.T) {
	files := routingFiles{
		Config: []byte("default 2;\nproxy_for 2 1.1.1.1:8888;\n"),
		Secret: bytes.Repeat([]byte{42}, 128),
	}
	encoded, err := json.Marshal(files)
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, bytes.Repeat([]byte{' '}, maxRoutingCache)...)
	storage := &certmagic.FileStorage{Path: t.TempDir()}
	ctx, cancel := context.WithCancel(t.Context())
	b := &backend{ctx: ctx, cancel: cancel, log: zap.NewNop(), routesReady: make(chan struct{})}
	t.Cleanup(b.close)
	if err := storage.Store(ctx, routingCacheKey, encoded); err != nil {
		t.Fatal(err)
	}
	transport := gatedRoutingFixture{routingFixture(files), make(chan struct{}), make(chan struct{})}
	b.wg.Go(func() { b.refreshLoop(storage, &http.Client{Transport: transport}) })
	timeout, stop := context.WithTimeout(t.Context(), 4*time.Second)
	defer stop()
	select {
	case <-transport.started:
	case <-timeout.Done():
		t.Fatal("route refresh did not fetch new routes")
	}
	if b.routes.Load() != nil {
		t.Fatal("published oversized cached routes")
	}
	close(transport.resume)
	select {
	case <-b.routesReady:
	case <-timeout.Done():
		t.Fatal("route refresh did not complete")
	}
	if current := b.routes.Load(); current == nil || len(current.targets(2)) != 1 {
		t.Fatal("route refresh did not recover from the oversized cache")
	}
}

func TestDialWaitsForRoutesAcrossColdRefreshFailure(t *testing.T) {
	t.Run("transport error", func(t *testing.T) { testDialWaitsForRoutesAcrossColdRefreshFailure(t, false) })
	t.Run("empty files", func(t *testing.T) { testDialWaitsForRoutesAcrossColdRefreshFailure(t, true) })
}

func testDialWaitsForRoutesAcrossColdRefreshFailure(t *testing.T, empty bool) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		b := &backend{ctx: ctx, cancel: cancel, log: zap.NewNop(), routesReady: make(chan struct{})}
		defer b.close()
		storage := &routingMemoryStorage{}
		files := routingFixture{
			Config: []byte("default 2;\nproxy_for 2 1.1.1.1:8888;\n"),
			Secret: bytes.Repeat([]byte{42}, 128),
		}
		attempts := 0
		client := &http.Client{Transport: routingTransportFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == telegramConfigURL {
				attempts++
			}
			if attempts == 1 {
				if empty {
					return (routingFixture{}).RoundTrip(req)
				}
				return nil, io.ErrUnexpectedEOF
			}
			return files.RoundTrip(req)
		})}
		b.wg.Go(func() { b.refreshLoop(storage, client) })
		synctest.Wait()
		if data, _ := storage.snapshot(); b.routes.Load() != nil || len(data) != 0 {
			t.Fatal("cold refresh failure published or cached routes")
		}
		time.Sleep(59 * time.Second)
		finished := make(chan error, 1)
		go func() {
			conn, err := b.dial(ctx, [16]byte{}, nil, nil)
			if conn != nil {
				_ = conn.Close()
			}
			finished <- err
		}()
		synctest.Wait()
		select {
		case err := <-finished:
			t.Fatalf("dial returned before the next refresh: %v", err)
		default:
		}
		if err := <-finished; err != nil {
			t.Fatalf("dial failed when the next refresh succeeded: %v", err)
		}
		synctest.Wait()
		if data, _ := storage.snapshot(); attempts != 2 || b.routes.Load() == nil || len(data) == 0 {
			t.Fatal("successful retry did not publish and cache routes")
		}
	})
}

func TestRefreshPreservesRoutesAndRetriesCacheWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		b := &backend{ctx: ctx, cancel: cancel, log: zap.NewNop(), routesReady: make(chan struct{})}
		defer b.close()
		old := routingFiles{
			Config: []byte("default 2;\nproxy_for 2 1.1.1.1:8888;\n"),
			Secret: bytes.Repeat([]byte{42}, 128),
		}
		updated := routingFiles{
			Config: []byte("default 2;\nproxy_for 2 8.8.8.8:8888;\n"),
			Secret: bytes.Repeat([]byte{19}, 128),
		}
		oldCache, err := json.Marshal(old)
		if err != nil {
			t.Fatal(err)
		}
		newCache, err := json.Marshal(updated)
		if err != nil {
			t.Fatal(err)
		}
		storage := &routingMemoryStorage{data: oldCache, failStores: 1}
		attempts := 0
		client := &http.Client{Transport: routingTransportFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == telegramConfigURL {
				attempts++
			}
			switch attempts {
			case 1:
				return routingFixture{Config: updated.Config, Secret: updated.Secret[:127]}.RoundTrip(req)
			case 2:
				return routingFixture(updated).RoundTrip(req)
			default:
				return nil, io.ErrUnexpectedEOF
			}
		})}
		b.wg.Go(func() { b.refreshLoop(storage, client) })
		synctest.Wait()
		select {
		case <-b.routesReady:
		default:
			t.Fatal("valid cache did not signal route readiness")
		}
		initial := b.routes.Load()
		data, stores := storage.snapshot()
		if initial == nil || !slices.Equal(initial.targets(2), []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:8888")}) ||
			initial.secret != [128]byte(old.Secret) || !bytes.Equal(data, oldCache) || stores != 0 {
			t.Fatal("invalid download changed the active or cached pair")
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		current := b.routes.Load()
		data, stores = storage.snapshot()
		if current == nil || current == initial || !slices.Equal(current.targets(2), []netip.AddrPort{netip.MustParseAddrPort("8.8.8.8:8888")}) ||
			current.secret != [128]byte(updated.Secret) || !bytes.Equal(data, oldCache) || stores != 1 {
			t.Fatal("a cache write error prevented publication or changed stored routes")
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		data, stores = storage.snapshot()
		if attempts != 3 || b.routes.Load() != current || !bytes.Equal(data, newCache) || stores != 2 {
			t.Fatal("download failure prevented retrying the pending cache write")
		}
	})
}

type routingMemoryStorage struct {
	certmagic.Storage
	mu         sync.Mutex
	data       []byte
	stores     int
	failStores int
}

func (s *routingMemoryStorage) Load(_ context.Context, _ string) ([]byte, error) {
	data, _ := s.snapshot()
	if data == nil {
		return nil, fs.ErrNotExist
	}
	return data, nil
}

func (s *routingMemoryStorage) Store(_ context.Context, _ string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stores++
	if s.stores <= s.failStores {
		return errors.New("test cache write failed")
	}
	s.data = data
	return nil
}

func (s *routingMemoryStorage) snapshot() ([]byte, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data, s.stores
}

type routingTransportFunc func(*http.Request) (*http.Response, error)

func (f routingTransportFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type gatedRoutingFixture struct {
	routingFixture
	started, resume chan struct{}
}

func (f gatedRoutingFixture) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.String() == telegramConfigURL {
		close(f.started)
		select {
		case <-f.resume:
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}
	}
	return f.routingFixture.RoundTrip(request)
}

type routingFixture routingFiles

func (f routingFixture) RoundTrip(request *http.Request) (*http.Response, error) {
	var contents []byte
	switch request.URL.String() {
	case telegramConfigURL:
		contents = f.Config
	case telegramSecretURL:
		contents = f.Secret
	default:
		return nil, fmt.Errorf("unexpected URL %s", request.URL)
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(contents))}, nil
}

func TestObfuscatedAdmissionWithIndependentWireVectors(t *testing.T) {
	// These AES-256-CTR vectors were generated with OpenSSL. The incoming
	// packet follows the header so it also tests the inbound counter position.
	const prefix = "8d454c41793132330102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"
	const invalidTail = "320b96ff6be24884b2ca312fa73a73c281bc61a8"
	const validTail = "dce578116be24884b2ca312fa73a73c281bc61a8"
	const encryptedReply = "b76c90a2af9ca1c9f7567072"
	secret := [16]byte{92}
	var replays handshakeReplays
	for _, step := range []struct {
		tail    string
		want    error
		entries int
	}{
		{invalidTail, errInvalidObfuscatedHandshake, 0},
		{validTail, nil, 1},
		{validTail, errHandshakeReplay, 1},
	} {
		encrypted, err := hex.DecodeString(prefix + step.tail)
		if err != nil {
			t.Fatal(err)
		}
		wire := bytes.NewBuffer(encrypted)
		client, err := acceptObfuscated(wire, secret, &replays)
		if err != step.want || len(replays.entries) != step.entries || wire.Len() != 12 {
			t.Fatalf("handshake returned %v with %d replay entries and %d unread bytes, want %v, %d, and 12", err, len(replays.entries), wire.Len(), step.want, step.entries)
		}
		if err != nil {
			continue
		}
		if client.tag != intermediate || client.dc != -2 {
			t.Fatalf("normal handshake returned tag %x and DC %d", client.tag, client.dc)
		}
		packet, quick, err := client.readPacket(nil)
		if err != nil || quick || !bytes.Equal(packet.payload(), []byte("telegram")) {
			t.Fatalf("incoming packet = %x, quick ack = %v, error = %v", packet.payload(), quick, err)
		}
		packet.release()
		if err := client.writer.writePacket(client.tag, []byte("telegram")); err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(wire.Bytes()); got != encryptedReply {
			t.Fatalf("reply encrypted to %s, want %s", got, encryptedReply)
		}
	}
}

func TestTransportPacketLimitAllowsPaddingAfterMaximumPayload(t *testing.T) {
	for _, extra := range []uint32{0, 1, 2, 3, 4} {
		for _, tag := range []uint32{intermediate, paddedIntermediate} {
			size := uint32(maxTransportPacket) + extra
			wire := le.AppendUint32(nil, size|0x80000000)
			var header [4]byte
			got, quick, err := transportPacketSize(bytes.NewReader(wire), tag, &header)
			if extra == 0 || (tag == paddedIntermediate && extra < 4) {
				if err != nil || !quick || got != size {
					t.Errorf("tag %x size %d returned %d, %t, %v", tag, size, got, quick, err)
				}
			} else if err == nil {
				t.Errorf("tag %x accepted oversized wire length %d", tag, size)
			}
		}
	}
}

func TestPaddedTransportWritesAcrossRandomnessRefills(t *testing.T) {
	key, iv := [32]byte{4}, [16]byte{2}
	var wire bytes.Buffer
	writer := transportWriter{stream: newTransportCTR(key, iv), destination: &wire}
	packet := make([]byte, 4+64, 4+64+3)
	payload := bytes.Repeat([]byte{0x8d}, len(packet)-4)
	ack := le.AppendUint32(le.AppendUint32(nil, 0xffffffff), 0x80000007)
	for i := range 64 {
		var err error
		if i%2 == 0 {
			err = writer.writeQuickAck(paddedIntermediate, 7)
		} else {
			copy(packet[4:], payload)
			err = writer.writePacketAt(paddedIntermediate, packet, 4)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	data := wire.Bytes()
	standardCTR(key, iv).XORKeyStream(data, data)
	for i := range 64 {
		want := ack
		if i%2 != 0 {
			want = payload
		}
		if len(data) < 4 {
			t.Fatalf("packet %d is missing its header", i)
		}
		size := int(le.Uint32(data))
		data = data[4:]
		if size < len(want) || size > len(want)+3 || size > len(data) ||
			!bytes.Equal(data[:len(want)], want) {
			t.Fatalf("packet %d has invalid padded wire size or body: %d", i, size)
		}
		data = data[size:]
	}
	if len(data) != 0 {
		t.Fatalf("%d extra wire bytes", len(data))
	}
}

type partialTransportWriter struct {
	writes int
	err    error
}

func (w *partialTransportWriter) Write(data []byte) (int, error) {
	w.writes++
	if w.writes == 1 {
		return len(data) / 2, w.err
	}
	return len(data), nil
}

func TestTransportWriterStopsAfterPartialWrite(t *testing.T) {
	for _, tc := range []struct {
		name     string
		tag      uint32
		ackFirst bool
		writeErr error
		wantErr  error
	}{
		{"short packet write", intermediate, false, nil, io.ErrShortWrite},
		{"partial acknowledgement with timeout", paddedIntermediate, true, os.ErrDeadlineExceeded, os.ErrDeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := &partialTransportWriter{err: tc.writeErr}
			writer := transportWriter{stream: newTransportCTR([32]byte{4}, [16]byte{2}), destination: wire}
			var err error
			if tc.ackFirst {
				err = writer.writeQuickAck(tc.tag, 7)
			} else {
				err = writer.writePacket(tc.tag, make([]byte, 64))
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("initial write returned %v, want %v", err, tc.wantErr)
			}

			packet := bytes.Repeat([]byte{0x8d}, 4+64)
			original := slices.Clone(packet)
			if err := writer.writePacketAt(tc.tag, packet, 4); !errors.Is(err, tc.wantErr) {
				t.Fatalf("packet after failed write returned %v, want %v", err, tc.wantErr)
			}
			if err := writer.writeQuickAck(tc.tag, 8); !errors.Is(err, tc.wantErr) {
				t.Fatalf("acknowledgement after failed write returned %v, want %v", err, tc.wantErr)
			}
			if wire.writes != 1 || !bytes.Equal(packet, original) {
				t.Fatalf("failed transport wrote %d times or changed a subsequent packet", wire.writes)
			}
		})
	}
}

func TestBackendCarriesMTProto(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	b := &backend{ctx: ctx, cancel: cancel, log: zap.NewNop()}
	t.Cleanup(b.close)
	routes := &routingConfig{
		dcs:    map[int16][]netip.AddrPort{2: {listener.Addr().(*net.TCPAddr).AddrPort()}},
		secret: [128]byte{24, 79, 87, 12},
	}
	b.routes.Store(routes)
	secret := [16]byte{42}
	request := make([]byte, 40)
	le.PutUint32(request[16:], 20)
	le.PutUint32(request[20:], 0xbe7e8ef1)
	response := bytes.Repeat([]byte{0x63, 0x24, 0x16, 0x05}, 16<<10)
	for name, tag := range map[string]uint32{
		"abridged": abridged, "intermediate": intermediate, "padded": paddedIntermediate,
	} {
		t.Run(name, func(t *testing.T) {
			deadline := time.Now().Add(4 * time.Second)
			_ = listener.SetDeadline(deadline)
			fixture := make(chan error, 1)
			go func() {
				fixture <- exchangeMiddleFixture(listener, deadline, routes.secret, request, response, tag)
			}()
			ready := make(chan error, 1)
			conn, err := b.dial(t.Context(), secret, new(handshakeReplays), func(err error) { ready <- err })
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(deadline)
			select {
			case err := <-ready:
				t.Fatalf("backend completed before receiving the handshake: %v", err)
			default:
			}
			stream, err := dialObfuscatedFixture(conn, tag, 2, secret[:])
			if err == nil {
				err = stream.writer.writePacket(tag, request)
			}
			if err == nil {
				var got []byte
				got, _, err = readTransportPacket(stream.reader, tag)
				if err == nil && !bytes.Equal(got, response) {
					err = fmt.Errorf("got %x, want %x", got, response)
				}
				if err == nil {
					if _, _, closeErr := readTransportPacket(stream.reader, tag); closeErr != io.EOF {
						err = fmt.Errorf("stream did not observe the upstream disconnect: %v", closeErr)
					}
				}
			}
			if fixtureErr := <-fixture; err != nil || fixtureErr != nil {
				t.Fatalf("client error %v, Telegram fixture error %v", err, fixtureErr)
			}
			if err := <-ready; err != nil {
				t.Fatalf("backend did not finish the handshake: %v", err)
			}
		})
	}
}

func TestBackendMultiplexesAndClosesStreamsIndependently(t *testing.T) {
	for _, transport := range []struct {
		name string
		tag  uint32
		ack  []byte
	}{
		{"abridged", abridged, []byte{0x84, 3, 2, 1}},
		{"intermediate", intermediate, []byte{1, 2, 3, 0x84}},
		{"padded intermediate", paddedIntermediate, []byte{0xff, 0xff, 0xff, 0xff, 1, 2, 3, 0x84}},
	} {
		t.Run(transport.name, func(t *testing.T) {
			testBackendMultiplexedStreams(t, transport.tag, transport.ack)
		})
	}
}

func testBackendMultiplexedStreams(t *testing.T, tag uint32, expectedAck []byte) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(t.Context())
	b := &backend{ctx: ctx, cancel: cancel, log: zap.NewNop()}
	defer b.close()
	routes := &routingConfig{
		dcs:    map[int16][]netip.AddrPort{2: {listener.Addr().(*net.TCPAddr).AddrPort()}},
		secret: [128]byte{24, 79, 87, 12},
	}
	b.routes.Store(routes)
	deadline := time.Now().Add(4 * time.Second)
	_ = listener.SetDeadline(deadline)
	fixture := make(chan error, 1)
	go func() {
		peer, err := listener.AcceptTCP()
		if err != nil {
			fixture <- err
			return
		}
		defer peer.Close()
		_ = peer.SetDeadline(deadline)
		fixture <- exchangeMultiplexedStreams(peer, routes.secret)
	}()

	var clients [2]net.Conn
	var readers [2]io.Reader
	var writers [2]transportWriter
	checkPing := func(i, padding int) {
		t.Helper()
		const nonce = 42
		var ping [transportPingSize]byte
		le.PutUint32(ping[:], rpcPing)
		le.PutUint64(ping[4:], nonce)
		if tag == paddedIntermediate {
			wire := le.AppendUint32(nil, uint32(len(ping)+padding))
			wire = append(wire, ping[:]...)
			wire = append(wire, bytes.Repeat([]byte{0xa7}, padding)...)
			if err := writers[i].write(wire); err != nil {
				t.Fatal(err)
			}
		} else if err := writers[i].writePacket(tag, ping[:]); err != nil {
			t.Fatal(err)
		}
		pong, _, err := readTransportPacket(readers[i], tag)
		if err != nil || len(pong) != len(ping) || le.Uint32(pong) != rpcPong || le.Uint64(pong[4:]) != nonce {
			t.Fatalf("local PING with %d padding bytes returned %x, error %v", padding, pong, err)
		}
	}
	request := make([]byte, 40)
	le.PutUint32(request[16:], 20)
	le.PutUint32(request[20:], 0xbe7e8ef1)
	for i := range clients {
		secret := [16]byte{byte(i + 1)}
		conn, err := b.dial(ctx, secret, new(handshakeReplays), func(error) {})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(deadline)
		stream, err := dialObfuscatedFixture(conn, tag, 2, secret[:])
		if err != nil {
			t.Fatal(err)
		}
		clients[i], readers[i], writers[i] = conn, stream.reader, stream.writer
		if i == 0 {
			if tag == paddedIntermediate {
				for padding := range 16 {
					checkPing(i, padding)
				}
			} else {
				checkPing(i, 0)
			}
			b.poolMu.Lock()
			dialed := len(b.pools) != 0
			b.poolMu.Unlock()
			if dialed {
				t.Fatal("local PING opened a Telegram RPC connection")
			}
		}
		le.PutUint32(request[24:], uint32(i+1))
		if err := writers[i].writePacket(tag, request); err != nil {
			t.Fatal(err)
		}
	}
	for i, reader := range readers {
		if i == 1 {
			var ack []byte
			var err error
			if tag == paddedIntermediate {
				ack, _, err = readTransportPacket(reader, tag)
			} else {
				ack = make([]byte, len(expectedAck))
				_, err = io.ReadFull(reader, ack)
			}
			if err != nil || !bytes.Equal(ack, expectedAck) {
				t.Fatalf("second stream quick ACK %x, want %x, error %v", ack, expectedAck, err)
			}
		}
		answer, _, err := readTransportPacket(reader, tag)
		if err != nil || len(answer) != 4 || le.Uint32(answer) != uint32(i+1) {
			t.Fatalf("stream %d answer %x, error %v", i+1, answer, err)
		}
	}
	if _, _, err := readTransportPacket(readers[0], tag); err != io.EOF {
		t.Fatalf("first stream close: %v", err)
	}
	if tag == paddedIntermediate {
		checkPing(1, 15)
	} else {
		checkPing(1, 0)
	}
	if err := writers[1].writePacket(tag, request); err != nil {
		t.Fatal(err)
	}
	answer, _, err := readTransportPacket(readers[1], tag)
	if err != nil || len(answer) != 4 || le.Uint32(answer) != 3 {
		t.Fatalf("second stream after first stream closed: answer %x, error %v", answer, err)
	}
	_ = clients[1].Close()
	if err := <-fixture; err != nil {
		t.Fatal(err)
	}
}

func exchangeMultiplexedStreams(conn *net.TCPConn, secret [128]byte) error {
	peer, err := negotiateMiddleFixture(conn, secret)
	if err != nil {
		return err
	}
	var ids [3]uint64
	for range 2 {
		packet, err := peer.read(maxRPCPacket)
		if err != nil {
			return err
		}
		if len(packet) != 96 || le.Uint32(packet) != rpcProxyReq {
			return fmt.Errorf("unexpected multiplexed request %x", packet)
		}
		index := le.Uint32(packet[80:])
		if index < 1 || index > 2 {
			return fmt.Errorf("unexpected request index %d", index)
		}
		ids[index] = le.Uint64(packet[8:])
	}
	if ids[1] == 0 || ids[2] == 0 || ids[1] == ids[2] {
		return fmt.Errorf("invalid multiplexed stream IDs %v", ids)
	}
	var ack [16]byte
	le.PutUint32(ack[:], rpcSimpleAck)
	le.PutUint64(ack[4:], ids[2])
	le.PutUint32(ack[12:], 0x84030201)
	if err := peer.write(ack[:]); err != nil {
		return err
	}
	var response [4]byte
	for index := 2; index >= 1; index-- {
		le.PutUint32(response[:], uint32(index))
		if err := writeMiddleAnswer(peer, ids[index], response[:]); err != nil {
			return err
		}
	}
	var closePacket [12]byte
	le.PutUint32(closePacket[:], rpcCloseExt)
	le.PutUint64(closePacket[4:], ids[1])
	if err := peer.write(closePacket[:]); err != nil {
		return err
	}
	packet, err := peer.read(maxRPCPacket)
	if err != nil {
		return err
	}
	if len(packet) != 96 || le.Uint32(packet) != rpcProxyReq || le.Uint64(packet[8:]) != ids[2] {
		return fmt.Errorf("unexpected request after remote close %x", packet)
	}
	le.PutUint32(response[:], 3)
	if err := writeMiddleAnswer(peer, ids[2], response[:]); err != nil {
		return err
	}
	packet, err = peer.read(maxRPCPacket)
	if err != nil {
		return err
	}
	if len(packet) != 12 || le.Uint32(packet) != rpcCloseConn || le.Uint64(packet[4:]) != ids[2] {
		return fmt.Errorf("unexpected local close notification %x", packet)
	}
	return nil
}

func dialObfuscatedFixture(conn io.ReadWriter, tag uint32, dc int16, secret []byte) (obfuscatedConn, error) {
	var header [64]byte
	rand.Read(header[:])
	le.PutUint32(header[56:], tag)
	le.PutUint16(header[60:], uint16(dc))
	material := (*[48]byte)(header[8:56])
	write := obfuscationStream(material[:], secret)
	read := reverseObfuscationStream(material, secret)
	encrypted := header
	write.XORKeyStream(encrypted[:], encrypted[:])
	copy(header[56:], encrypted[56:])
	if err := writeFull(conn, header[:]); err != nil {
		return obfuscatedConn{}, err
	}
	return obfuscatedConn{
		reader: &cipher.StreamReader{S: read, R: conn},
		writer: transportWriter{stream: write, destination: conn},
	}, nil
}

func exchangeMiddleFixture(listener *net.TCPListener, deadline time.Time, secret [128]byte, request, response []byte, tag uint32) error {
	conn, err := listener.AcceptTCP()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	peer, err := negotiateMiddleFixture(conn, secret)
	if err != nil {
		return err
	}
	packet, err := peer.read(maxRPCPacket)
	if err != nil {
		return err
	}
	flags := uint32(0x20021002)
	if tag == abridged {
		flags = 0x40021002
	}
	if len(packet) != 56+len(request) || le.Uint32(packet) != rpcProxyReq || le.Uint32(packet[4:]) != flags || !bytes.Equal(packet[56:], request) {
		return fmt.Errorf("unexpected request %x", packet)
	}
	local := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
	if [16]byte(packet[36:52]) != local.Addr().Unmap().As16() {
		return fmt.Errorf("proxy address does not match the connection family and source")
	}
	return writeMiddleAnswer(peer, le.Uint64(packet[8:]), response)
}

func negotiateMiddleFixture(conn *net.TCPConn, secret [128]byte) (*middleConn, error) {
	peer := &middleConn{conn: conn, reader: conn, readSeq: -2, writeSeq: -2}
	nonce, err := peer.read(rpcHandshakePacket)
	if err != nil {
		return nil, err
	}
	if len(nonce) != 32 || le.Uint32(nonce) != rpcNonce || !bytes.Equal(nonce[4:8], secret[:4]) {
		return nil, fmt.Errorf("unexpected nonce %x", nonce)
	}
	reply := bytes.Clone(nonce)
	copy(reply[16:], "test-server-salt")
	if err := peer.write(reply); err != nil {
		return nil, err
	}
	timestamp := le.Uint32(nonce[12:])
	local, remote := conn.RemoteAddr().(*net.TCPAddr).AddrPort(), conn.LocalAddr().(*net.TCPAddr).AddrPort()
	keys := middleSessionKeys([16]byte(reply[16:]), [16]byte(nonce[16:]), timestamp, local, remote, &secret)
	writeKey, writeIV := keys[serverDirection].key, keys[serverDirection].iv
	readKey, readIV := keys[clientDirection].key, keys[clientDirection].iv
	encrypt, _ := aes.NewCipher(writeKey[:])
	decrypt, _ := aes.NewCipher(readKey[:])
	peer.encrypt = cipher.NewCBCEncrypter(encrypt, writeIV[:])
	peer.reader = &cbcReader{source: conn, decrypt: cipher.NewCBCDecrypter(decrypt, readIV[:])}
	handshake, err := peer.read(rpcHandshakePacket)
	if err != nil {
		return nil, err
	}
	if len(handshake) != 32 || le.Uint32(handshake) != rpcHandshake {
		return nil, fmt.Errorf("unexpected handshake %x", handshake)
	}
	copy(handshake[20:], handshake[8:20])
	if err := peer.write(handshake); err != nil {
		return nil, err
	}
	return peer, nil
}

func writeMiddleAnswer(peer *middleConn, id uint64, response []byte) error {
	var answer [16]byte
	le.PutUint32(answer[:], rpcProxyAns)
	le.PutUint64(answer[8:], id)
	return peer.write(answer[:], response)
}
