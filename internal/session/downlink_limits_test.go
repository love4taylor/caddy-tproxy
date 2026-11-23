package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net"
	"testing"
	"time"

	"github.com/love4taylor/caddy-tproxy/internal/config"
	"github.com/love4taylor/caddy-tproxy/internal/frame"
)

type readStartedConn struct {
	net.Conn
	started chan struct{}
}

func (c *readStartedConn) Read(dst []byte) (int, error) {
	select {
	case c.started <- struct{}{}:
	default:
	}
	return c.Conn.Read(dst)
}

func TestAdmittedReadSurvivesConcurrentGlobalBudgetUse(t *testing.T) {
	cfg := lifecycleConfig(config.CarrierHTTPS)
	cfg.Limits.MaxSessionsGlobal = 1
	local, peer := net.Pipe()
	reader := &readStartedConn{Conn: local, started: make(chan struct{}, 1)}
	cfg.Profiles[0].DialBackend = func(_ context.Context, ready func(error)) (net.Conn, error) {
		ready(nil)
		return reader, nil
	}
	manager := NewManager(cfg, [32]byte{8})
	t.Cleanup(manager.Shutdown)
	t.Cleanup(func() { _ = peer.Close() })
	s := establish(t, manager, &cfg.Profiles[0]).Session
	t.Cleanup(s.Close)
	const id = 1
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, err := s.ProcessUp(1, frame.Encode(frame.Open, id, nil))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-reader.started:
	case <-ctx.Done():
		t.Fatal("backend did not start reading")
	}
	controlBytes, _ := pendingControlReserve(cfg.Limits)
	available := cfg.Limits.MaxPendingGlobal - controlBytes - int(manager.Capacity().PendingBytes)
	held := available - 1
	if !manager.ChangeBufferBudget(held) {
		t.Fatal("could not fill the remaining global data budget")
	}
	defer func() { manager.ChangeBufferBudget(-held) }()
	payload := []byte("downlink under pressure")
	if err := peer.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := peer.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("backend write returned %d, %v", n, err)
	}
	batch, _, err := s.Poll(ctx, 0)
	if err != nil || batch == nil {
		t.Fatalf("backend read was lost: %v", err)
	}
	parsed, err := frame.ParseAll(readDownlink(t, batch), frame.MaxPayload)
	if err != nil || len(parsed) != 1 || parsed[0].Type != frame.Data ||
		parsed[0].StreamID != id || !bytes.Equal(parsed[0].Payload, payload) {
		t.Fatalf("wanted the admitted DATA frame, got %v (%v)", parsed, err)
	}
	awaitState(t, func() bool {
		manager.budgetMu.Lock()
		defer manager.budgetMu.Unlock()
		return manager.budgetChanged != nil
	})
	manager.ChangeBufferBudget(-held)
	held = 0
	select {
	case <-reader.started:
	case <-ctx.Done():
		t.Fatal("reading did not resume after global budget was released")
	}
	s.Close()
	awaitState(t, func() bool {
		got := manager.Capacity()
		return got.PendingBytes == 0 && got.PendingItems == 0 && got.Streams == 0
	})
}

func TestDataCoalescingRespectsCarrierAndAllocationBounds(t *testing.T) {
	settings := config.Defaults()
	settings.Limits.CarrierBatchBytes = 256 << 10
	profile := config.Profile{CarrierMode: config.CarrierHTTPS}
	s := newSession(sessionOptions{profile: &profile, limits: settings.Limits, timeouts: settings.Timeouts})
	defer s.Close()
	const blocks = 7
	data := make([]byte, frame.DataChunk)
	s.mu.Lock()
	for range blocks {
		if !s.queueFrameLocked(frame.Data, 1, data) {
			s.mu.Unlock()
			t.Fatal("valid downlink was rejected")
		}
	}
	allocated := 0
	for _, encoded := range s.pendingFrames {
		allocated += cap(encoded) + queueItemCost
	}
	if allocated != s.pendingCost {
		s.mu.Unlock()
		t.Fatalf("downlink charged %d bytes for %d bytes of allocated storage", s.pendingCost, allocated)
	}
	s.mu.Unlock()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var cursor uint64
	for delivered := 0; delivered < blocks*len(data); {
		batch, next, err := s.Poll(ctx, cursor)
		if err != nil || batch == nil {
			t.Fatalf("failed to drain queue: %v", err)
		}
		body := readDownlink(t, batch)
		if len(body) > settings.Limits.CarrierBatchBytes {
			t.Fatalf("carrier sent %d bytes above its negotiated maximum", len(body))
		}
		parts, err := frame.ParseAll(body, settings.Limits.MaxFramePayload)
		if err != nil {
			t.Fatal(err)
		}
		for _, chunk := range parts {
			if len(chunk.Payload) > frame.DataChunk {
				t.Fatalf("relay emitted a DATA payload of %d bytes", len(chunk.Payload))
			}
			delivered += len(chunk.Payload)
		}
		cursor = next
	}
}

func TestHTTPDownlinkReplaysAfterPartialWrite(t *testing.T) {
	for _, mode := range []config.CarrierMode{config.CarrierHTTPS, config.CarrierHTTPSLanes} {
		t.Run(string(mode), func(t *testing.T) { testHTTPDownlinkReplaysAfterPartialWrite(t, mode) })
	}
}

func testHTTPDownlinkReplaysAfterPartialWrite(t *testing.T, mode config.CarrierMode) {
	cfg := lifecycleConfig(mode)
	manager := NewManager(cfg, [32]byte{8})
	t.Cleanup(manager.Shutdown)
	s := establish(t, manager, &cfg.Profiles[0]).Session
	first := bytes.Repeat([]byte{1}, frame.DataChunk)
	second := bytes.Repeat([]byte{2}, frame.DataChunk)
	const firstID uint32 = 1
	secondID := uint32(3)
	queue := &s.downQueue
	poll := s.Poll
	s.mu.Lock()
	if mode == config.CarrierHTTPSLanes {
		lane := newCarrierLane()
		s.carrierLanes[firstID] = lane
		s.rememberClosedLocked(firstID)
		queue = &lane.downQueue
		secondID = firstID
		poll = func(ctx context.Context, cursor uint64) (*Downlink, uint64, error) {
			batch, next, closed, err := s.PollLane(ctx, firstID, cursor)
			if closed {
				return nil, next, io.EOF
			}
			return batch, next, err
		}
	}
	queued := s.queueFrameLocked(frame.Data, firstID, first) && s.queueFrameLocked(frame.Data, secondID, second)
	s.mu.Unlock()
	if !queued {
		t.Fatal("could not queue two DATA frames")
	}
	// A response can consume the buffers already admitted even if no room
	// remains in the global DATA budget for a second copy.
	limit := manager.pendingLimits[pendingDownlink].bytes
	held := limit - int(manager.Capacity().PendingBytes)
	if held <= 0 || !manager.ChangeBufferBudget(held) {
		t.Fatal("could not fill the global DATA budget")
	}
	defer manager.ChangeBufferBudget(-held)
	want := append(frame.Encode(frame.Data, firstID, first), frame.Encode(frame.Data, secondID, second)...)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	batch, cursor, err := poll(ctx, 0)
	if err != nil || cursor != 1 || batch == nil {
		t.Fatalf("could not poll for queued DATA: cursor %d, error %v", cursor, err)
	}
	defer batch.Release()
	if got := batch.Len(); got != len(want) {
		t.Fatalf("content length = %d, want %d", got, len(want))
	}
	var sent bytes.Buffer
	broken := writeFunc(func(part []byte) (int, error) {
		if sent.Len() > 0 {
			return sent.Write(part[:16])
		}
		return sent.Write(part)
	})
	if n, err := batch.WriteTo(broken); !errors.Is(err, io.ErrShortWrite) || n != int64(frame.HeaderSize+len(first)+16) {
		t.Fatalf("broken write returned %d bytes, %v", n, err)
	}
	if !bytes.Equal(sent.Bytes(), want[:sent.Len()]) {
		t.Fatal("partial write changed the response")
	}
	window := frame.WindowPayload(4)
	s.mu.Lock()
	queued = s.queueFrameLocked(frame.Window, firstID, window)
	s.mu.Unlock()
	if !queued {
		t.Fatal("could not queue a control frame during a borrowed response")
	}
	type pollResult struct {
		batch  *Downlink
		cursor uint64
		err    error
	}
	retry := func() <-chan pollResult {
		out := make(chan pollResult, 1)
		go func() {
			replay, next, err := poll(ctx, 0)
			out <- pollResult{replay, next, err}
		}()
		return out
	}
	firstRetry := retry()
	awaitState(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return queue.waiter != nil
	})
	secondRetry := retry()
	if old := <-firstRetry; old.err != nil || old.batch != nil || old.cursor != 0 {
		t.Fatalf("superseded retry returned %+v", old)
	}
	batch.Release()
	wantPending := int64(held + len(want) + frame.HeaderSize + len(window) + 3*queueItemCost)
	if pending := manager.Capacity().PendingBytes; pending != wantPending {
		t.Fatalf("pending bytes before acknowledgement = %d, want %d", pending, wantPending)
	}
	replay := <-secondRetry
	if replay.err != nil || replay.cursor != 1 || replay.batch == nil {
		t.Fatalf("could not replay response: %+v", replay)
	}
	if !bytes.Equal(readDownlink(t, replay.batch), want) {
		t.Fatal("replay changed the response bytes")
	}
	tail, next, err := poll(ctx, replay.cursor)
	if err != nil || next != 2 || tail == nil {
		t.Fatalf("could not poll the new response: cursor %d, error %v", next, err)
	}
	if !bytes.Equal(readDownlink(t, tail), frame.Encode(frame.Window, firstID, window)) {
		t.Fatal("the replay overwrote the next response")
	}
	wantPending -= int64(len(want) + 2*queueItemCost)
	if pending := manager.Capacity().PendingBytes; pending != wantPending {
		t.Fatalf("pending bytes after acknowledgement = %d, want %d", pending, wantPending)
	}
	s.Close()
	if s.pendingCost != 0 || s.pendingItems != 0 {
		t.Fatal("response budget leaked after retirement")
	}
}

func TestWindowCoalescingAcrossDownlinkBatches(t *testing.T) {
	for _, tc := range []struct {
		name         string
		extraWindows int
	}{
		{"few pending windows", 0},
		{"many pending windows", 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := lifecycleConfig(config.CarrierHTTPS)
			cfg.Limits.CarrierBatchBytes = 256 << 10
			manager := NewManager(cfg, [32]byte{8})
			t.Cleanup(manager.Shutdown)
			s := establish(t, manager, &cfg.Profiles[0]).Session
			queue := func(kind frame.Type, id uint32, payload []byte) {
				t.Helper()
				s.mu.Lock()
				queued := s.queueFrameLocked(kind, id, payload)
				s.mu.Unlock()
				if !queued {
					t.Fatalf("could not queue frame type %d for stream %d", kind, id)
				}
			}
			queueWindow := func(id, amount uint32) {
				t.Helper()
				queue(frame.Window, id, frame.WindowPayload(amount))
			}
			encodedWindow := func(id, amount uint32) []byte {
				return frame.Encode(frame.Window, id, frame.WindowPayload(amount))
			}

			const dataFrames = 4
			queueWindow(1, math.MaxUint32)
			queueWindow(3, 11)
			wantHead := make([]byte, 0, cfg.Limits.CarrierBatchBytes)
			wantHead = append(wantHead, encodedWindow(1, math.MaxUint32)...)
			wantHead = append(wantHead, encodedWindow(3, 11)...)
			payload := bytes.Repeat([]byte{7}, (cfg.Limits.CarrierBatchBytes-len(wantHead))/dataFrames-frame.HeaderSize)
			for i := range dataFrames {
				id := uint32(5 + 2*i)
				queue(frame.Data, id, payload)
				wantHead = append(wantHead, frame.Encode(frame.Data, id, payload)...)
			}
			queueWindow(1, 1)
			for i := range tc.extraWindows {
				queueWindow(uint32(21+2*i), 9)
			}

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			poll := func(cursor uint64) *Downlink {
				t.Helper()
				batch, next, err := s.Poll(ctx, cursor)
				if err != nil || next != cursor+1 || batch == nil {
					t.Fatalf("poll at cursor %d returned cursor %d, error %v", cursor, next, err)
				}
				t.Cleanup(batch.Release)
				return batch
			}
			head := poll(0)
			queueWindow(1, 2)
			queueWindow(3, 12)
			if !bytes.Equal(readDownlink(t, head), wantHead) || !bytes.Equal(readDownlink(t, poll(0)), wantHead) {
				t.Fatal("updates changed the borrowed batch or its replay")
			}
			wantTail := encodedWindow(1, 3)
			for i := range tc.extraWindows {
				wantTail = append(wantTail, encodedWindow(uint32(21+2*i), 9)...)
			}
			wantTail = append(wantTail, encodedWindow(3, 12)...)
			if !bytes.Equal(readDownlink(t, poll(1)), wantTail) {
				t.Fatal("remaining WINDOW frames lost their order or increments")
			}
			s.Close()
			if s.pendingCost != 0 || s.pendingItems != 0 {
				t.Fatal("response budget leaked after retirement")
			}
		})
	}
}

func TestWebSocketDownlinkKeepsBorrowedStorageUntilRelease(t *testing.T) {
	cfg := config.Defaults()
	profile := config.Profile{CarrierMode: config.CarrierWebSocket}
	s := newSession(sessionOptions{profile: &profile, limits: cfg.Limits, timeouts: cfg.Timeouts})
	t.Cleanup(s.Close)
	queue := func(value byte) []byte {
		first := bytes.Repeat([]byte{value}, frame.DataChunk)
		second := bytes.Repeat([]byte{value + 1}, frame.DataChunk)
		if !s.queueFrameLocked(frame.Data, 1, first) || !s.queueFrameLocked(frame.Data, 2, second) {
			t.Fatal("could not queue DATA")
		}
		return append(frame.Encode(frame.Data, 1, first), frame.Encode(frame.Data, 2, second)...)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	wantFirst := queue(3)
	first, cursor, err := s.Poll(ctx, 0)
	if err != nil || first == nil {
		t.Fatalf("first batch: %v", err)
	}
	defer first.Release()
	wantSecond := queue(19)
	second, _, err := s.Poll(ctx, cursor)
	if err != nil || second == nil {
		t.Fatalf("second batch: %v", err)
	}
	defer second.Release()
	s.Close()
	firstBytes, secondBytes := first.WebSocketMessage(), second.WebSocketMessage()
	if !bytes.Equal(firstBytes, wantFirst) || !bytes.Equal(secondBytes, wantSecond) {
		t.Fatal("a borrowed WebSocket batch changed before release")
	}
	if cap(firstBytes) == len(firstBytes) {
		t.Fatal("media batch did not use a reusable size class")
	}
	if cap(firstBytes)+cap(secondBytes) > s.pendingCost || s.pendingItems != 4 {
		t.Fatalf("retained batches charged %d bytes and %d items", s.pendingCost, s.pendingItems)
	}
	first.Release()
	second.Release()
	if s.pendingCost != 0 || s.pendingItems != 0 {
		t.Fatal("WebSocket batches retained budget after release")
	}
}

func TestRetiredDownlinkDoesNotRecycleActiveFrame(t *testing.T) {
	cfg := config.Defaults()
	profile := config.Profile{CarrierMode: config.CarrierHTTPS}
	s := newSession(sessionOptions{profile: &profile, limits: cfg.Limits, timeouts: cfg.Timeouts})
	t.Cleanup(s.Close)
	const id = 1
	backend := newBackendStream(s, id)
	s.streams[id] = &streamState{backend: backend, sendCredit: frame.InitialStreamWindow}
	n := s.reserveBackendRead(backend, frame.DataChunk, nil)
	if n != frame.DataChunk {
		t.Fatalf("reserved %d bytes, want %d", n, frame.DataChunk)
	}
	storage := borrowBackendReadBuffer(frame.HeaderSize + n)
	data := []byte("short reply in reusable storage")
	copy(storage[frame.HeaderSize:], data)
	if !s.finishBackendRead(backend, storage, len(data)) {
		t.Fatal("could not queue downlink")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	batch, _, err := s.Poll(ctx, 0)
	if err != nil || batch == nil {
		t.Fatalf("could not borrow downlink: %v", err)
	}
	defer batch.Release()
	s.Close()
	var borrowed [][]byte
	defer func() {
		for _, other := range borrowed {
			recycleDownlinkFrame(other)
		}
	}()
	for range cap(backendReadBuffers) {
		other := borrowBackendReadBuffer(backendReadBufferSize)
		borrowed = append(borrowed, other)
		if &other[0] == &storage[0] {
			t.Fatal("reused a buffer that is still being written")
		}
	}
	if got := readDownlink(t, batch); !bytes.Equal(got, frame.Encode(frame.Data, id, data)) {
		t.Fatal("published bytes outside the completed read or changed the frame")
	}
	if s.pendingCost != 0 || s.pendingItems != 0 {
		t.Fatal("retired read retained its budget after release")
	}
	reused := borrowBackendReadBuffer(backendReadBufferSize)
	if &reused[0] != &storage[0] {
		t.Fatal("retired frame was not recycled after its writer released it")
	}
	recycleDownlinkFrame(reused)
}

type writeFunc func([]byte) (int, error)

func (w writeFunc) Write(part []byte) (int, error) { return w(part) }

func readDownlink(t *testing.T, batch *Downlink) []byte {
	t.Helper()
	defer batch.Release()
	var buffer bytes.Buffer
	buffer.Grow(batch.Len())
	if n, err := batch.WriteTo(&buffer); err != nil || n != int64(batch.Len()) {
		t.Fatalf("downlink write returned %d bytes, %v", n, err)
	}
	return buffer.Bytes()
}
