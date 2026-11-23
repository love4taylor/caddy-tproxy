package session

import (
	"bytes"
	"errors"
	"testing"
	"testing/synctest"

	"github.com/love4taylor/caddy-tproxy/internal/config"
	"github.com/love4taylor/caddy-tproxy/internal/frame"
)

func TestSmallUplinkFramesFitOneBackendWriteReservation(t *testing.T) {
	cfg := config.Defaults()
	cfg.Limits.MaxFramePayload = 4
	s := newSession(sessionOptions{profile: &config.Profile{}, limits: cfg.Limits, timeouts: cfg.Timeouts})
	t.Cleanup(s.Close)
	first, second := s.attachStream(1), s.attachStream(2)
	body := make([]byte, 0, frame.MaxBatchFrames*(frame.HeaderSize+4))
	want := make([]byte, 0, frame.MaxBatchFrames*4)
	for i := range frame.MaxBatchFrames {
		payload := []byte{byte(i >> 8), byte(i), 0x62, 0xa1}
		body = append(body, frame.Encode(frame.Data, first.id, payload)...)
		want = append(want, payload...)
	}
	cost := len(want) + queueItemCost
	room := s.pendingLimits[pendingUplink]
	heldBytes, heldItems := room.bytes-cost, room.items-1
	if !s.reservePendingLocked(heldBytes, heldItems, pendingUplink) {
		t.Fatal("could not reserve the rest of the uplink budget")
	}
	twoStreams := append(bytes.Clone(body[:frame.HeaderSize+4]), frame.Encode(frame.Data, second.id, want[:4])...)
	if _, err := s.ProcessUp(1, twoStreams); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("two backend writes with one slot returned %v", err)
	}
	for range 2 {
		if ack, err := s.ProcessUp(1, body); err != nil || ack != 1 {
			t.Fatalf("one backend write with one slot returned ack %d, error %v", ack, err)
		}
	}
	if s.pendingCost != room.bytes || s.pendingItems != room.items ||
		s.streams[first.id].receiveWindow != frame.InitialStreamWindow-uint32(len(want)) ||
		s.streams[second.id].receiveWindow != frame.InitialStreamWindow {
		t.Fatal("unexpected budget, flow credit, or duplicate commit")
	}
	data, state := s.nextWrite(first)
	if state == nil || !bytes.Equal(data, want) {
		t.Fatal("coalesced write changed the payload")
	}
	s.backendWriteFinished(state)
	s.releasePendingLocked(heldBytes, heldItems)
	if s.pendingCost != 0 || s.pendingItems != 0 {
		t.Fatal("upload left pending capacity")
	}
}

func TestSmallDataLimitAllowsSessionPong(t *testing.T) {
	for _, mode := range []config.CarrierMode{config.CarrierHTTPS, config.CarrierHTTPSLanes, config.CarrierWebSocket} {
		t.Run(string(mode), func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Limits.MaxFramePayload = 4
			s := newSession(sessionOptions{profile: &config.Profile{CarrierMode: mode}, limits: cfg.Limits, timeouts: cfg.Timeouts})
			t.Cleanup(s.Close)
			s.attachStream(1)
			submit := func(id uint32, seq uint64, body []byte) (uint64, error) {
				switch mode {
				case config.CarrierHTTPSLanes:
					return s.ProcessUpLane(id, seq, body)
				case config.CarrierWebSocket:
					return s.ProcessWebSocket(t.Context(), id, seq, body)
				default:
					return s.ProcessUp(seq, body)
				}
			}
			if ack, err := submit(0, 1, frame.Encode(frame.Pong, 0, make([]byte, 64))); err != nil || ack != 1 {
				t.Fatalf("valid PONG returned ACK %d, error %v", ack, err)
			}
			if _, err := submit(0, 2, frame.Encode(frame.Pong, 0, make([]byte, 65))); err == nil {
				t.Fatal("accepted oversized PONG")
			}
			id, seq := uint32(0), uint64(2)
			if mode == config.CarrierHTTPSLanes {
				id, seq = 1, 1
			}
			if _, err := submit(id, seq, frame.Encode(frame.Data, 1, make([]byte, 5))); err == nil {
				t.Fatal("accepted DATA above configured limit")
			}
		})
	}
}

func TestProfilePendingLimitsKeepRoomForUplinkAndControl(t *testing.T) {
	cfg := lifecycleConfig(config.CarrierHTTPS)
	profile := &cfg.Profiles[0]
	profile.Limits.MaxStreamsPerSession = 3
	profile.Limits.MaxPendingPerSession = 8 << 20
	manager := NewManager(cfg, [32]byte{11})
	t.Cleanup(manager.Shutdown)
	s := establish(t, manager, profile).Session
	limits := cfg.Limits
	limits.MaxStreamsPerSession = profile.Limits.MaxStreamsPerSession
	limits.MaxPendingPerSession = profile.Limits.MaxPendingPerSession
	data := pendingLimit(limits, pendingDownlink)
	uplink := pendingLimit(limits, pendingUplink)
	control := pendingLimit(limits, pendingControl)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reservePendingLocked(data.bytes+1, 0, pendingDownlink) || s.reservePendingLocked(1, data.items+1, pendingDownlink) {
		t.Fatal("downlink exceeded the profile's data limit")
	}
	if !s.reservePendingLocked(data.bytes, data.items, pendingDownlink) {
		t.Fatal("could not use the full downlink quota")
	}
	if s.dataFrameAllowanceLocked(frame.DataChunk) != 0 {
		t.Fatal("downlink reader could use the uplink or control reserve")
	}
	if !s.reservePendingLocked(uplink.bytes-data.bytes, uplink.items-data.items, pendingUplink) {
		t.Fatal("downlink consumed the uplink reserve")
	}
	if s.reservePendingLocked(1, 1, pendingUplink) {
		t.Fatal("uplink used the control reserve")
	}
	if !s.reservePendingLocked(control.bytes-uplink.bytes, control.items-uplink.items, pendingControl) {
		t.Fatal("uplink consumed the control reserve")
	}
	s.releasePendingLocked(control.bytes, control.items)
	if capacity := manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 {
		t.Fatalf("budget release left pending capacity: %+v", capacity)
	}
}

func TestActiveWriteKeepsItsBudgetUntilReleased(t *testing.T) {
	cfg := config.Defaults()
	s := newSession(sessionOptions{profile: &config.Profile{}, limits: cfg.Limits, timeouts: cfg.Timeouts})
	backend := newBackendStream(s, 1)
	stream := &streamState{backend: backend, receiveWindow: frame.InitialStreamWindow - 200}
	s.streams[backend.id] = stream
	for range 2 {
		if !s.reservePendingLocked(100+queueItemCost, 1, pendingUplink) {
			t.Fatal("could not reserve uplink")
		}
		cost, items := s.appendBackendWriteLocked(stream, []frame.Frame{{Payload: make([]byte, 100)}}, 100)
		s.releasePendingLocked(100+queueItemCost-cost, 1-items)
	}
	data, state := s.nextWrite(backend)
	if state != stream || len(data) != 200 {
		t.Fatal("queued writes did not coalesce")
	}
	cost := cap(data) + queueItemCost
	if s.pendingCost != cost || !s.backendDrained(backend, 100) || s.pendingCost < cost {
		t.Fatal("a partial write prematurely released its allocation")
	}
	const queuedSize = frame.DataChunk
	for range 3 {
		if !s.reservePendingLocked(queuedSize+queueItemCost, 1, pendingUplink) {
			t.Fatal("could not reserve a queued write")
		}
		queued, items := s.appendBackendWriteLocked(stream, []frame.Frame{{Payload: make([]byte, queuedSize)}}, queuedSize)
		if queued != queuedSize+queueItemCost || items != 1 {
			t.Fatal("a new write did not reserve its own buffer")
		}
	}
	s.Close()
	if s.pendingCost != cost || s.pendingItems != 1 {
		t.Fatal("closing the session released a buffer still owned by the writer")
	}
	s.backendWriteFinished(state)
	if s.pendingCost != 0 || s.pendingItems != 0 {
		t.Fatal("writer did not release its retired buffer")
	}
}

func TestUploadCombinesConsecutiveDataWithoutRetainingCarrierBody(t *testing.T) {
	cfg := config.Defaults()
	s := newSession(sessionOptions{profile: &config.Profile{}, limits: cfg.Limits, timeouts: cfg.Timeouts})
	t.Cleanup(s.Close)
	first, second := s.attachStream(1), s.attachStream(2)
	const chunk = frame.DataChunk / 4
	var batches [2][]byte
	want := make([][]byte, 4)
	groups := []int{0, 0, 0, 0, 1, 1, 2, 2, 2, 2, 3, 3, 3}
	for i, group := range groups {
		id := first.id
		if group == 1 {
			id = second.id
		}
		payload := bytes.Repeat([]byte{byte(i + 1)}, chunk)
		batch := 0
		if i >= 2 {
			batch = 1
		}
		batches[batch] = append(batches[batch], frame.Encode(frame.Data, id, payload)...)
		want[group] = append(want[group], payload...)
	}
	for i, body := range batches {
		sequence := uint64(i + 1)
		if ack, err := s.ProcessUp(sequence, body); err != nil || ack != sequence {
			t.Fatalf("upload %d ack %d, error %v", sequence, ack, err)
		}
		clear(body)
	}
	if s.pendingCost != len(groups)*chunk+len(want)*queueItemCost || s.pendingItems != len(want) {
		t.Fatalf("queued budget is %d bytes and %d items", s.pendingCost, s.pendingItems)
	}
	for i, stream := range []*backendStream{first, second, first, first} {
		data, state := s.nextWrite(stream)
		if state == nil || !bytes.Equal(data, want[i]) {
			t.Fatalf("unexpected bytes in queued write %d, size %d", i, len(data))
		}
		s.backendWriteFinished(state)
	}
	if writes := s.streams[first.id].writes; writes != nil {
		t.Fatal("drained multi-entry queue retained its backing array")
	}
	if writes := s.streams[second.id].writes; len(writes) != 0 || cap(writes) != 1 || writes[:1][0] != nil {
		t.Fatal("drained single-entry queue did not retain exactly one cleared slot")
	}
	if s.pendingCost != 0 || s.pendingItems != 0 {
		t.Fatal("writes did not return all of the upload budget")
	}
}

func TestWebSocketUploadKeepsParsedFramesWhileWaitingForBudget(t *testing.T) {
	for _, mode := range []config.CarrierMode{config.CarrierWebSocket, config.CarrierWebSocketLanes} {
		t.Run(string(mode), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := lifecycleConfig(mode)
				s := newSession(sessionOptions{profile: &cfg.Profiles[0], limits: cfg.Limits, timeouts: cfg.Timeouts})
				defer s.Close()
				backend := s.attachStream(1)
				var lane uint32
				if mode == config.CarrierWebSocketLanes {
					lane = backend.id
				}
				if !s.ClaimWebSocket(lane) {
					t.Fatal("could not claim test WebSocket")
				}
				room := s.pendingLimits[pendingUplink]
				if !s.reservePendingLocked(room.bytes, room.items, pendingUplink) {
					t.Fatal("could not fill uplink budget")
				}
				var body, want []byte
				for i := range 16 {
					payload := []byte{byte(i), byte(i + 1), 43, 86}
					body = append(body, frame.Encode(frame.Data, backend.id, payload)...)
					want = append(want, payload...)
				}
				type result struct {
					ack uint64
					err error
				}
				done := make(chan result, 1)
				go func() {
					ack, err := s.ProcessWebSocket(t.Context(), lane, 1, body)
					done <- result{ack, err}
				}()
				synctest.Wait()
				select {
				case got := <-done:
					t.Fatalf("upload did not wait for its quota: %+v", got)
				default:
				}
				s.mu.Lock()
				s.releasePendingLocked(room.bytes, room.items)
				s.mu.Unlock()
				if got := <-done; got.ack != 1 || got.err != nil {
					t.Fatalf("upload after budget release returned %+v", got)
				}
				clear(body)
				data, state := s.nextWrite(backend)
				if state == nil || !bytes.Equal(data, want) {
					t.Fatal("queued data changed after the carrier body was reused")
				}
				s.backendWriteFinished(state)
				if s.pendingCost != 0 || s.pendingItems != 0 {
					t.Fatal("upload did not return its quota")
				}
			})
		})
	}
}
