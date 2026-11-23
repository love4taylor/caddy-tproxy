package session

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/love4taylor/caddy-tproxy/internal/config"
	"github.com/love4taylor/caddy-tproxy/internal/frame"
)

func lifecycleConfig(mode config.CarrierMode) config.Config {
	cfg := config.Defaults()
	cfg.Profiles = []config.Profile{{Name: "relay", CarrierMode: mode, Capability: [32]byte{17, 33}}}
	return cfg
}

func awaitState(t *testing.T, check func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !check() {
		select {
		case <-ctx.Done():
			t.Fatal("state transition did not complete")
		case <-tick.C:
		}
	}
}

func establish(t *testing.T, manager *Manager, profile *config.Profile) CreateResult {
	t.Helper()
	ticket, err := manager.IssueBootstrap(profile, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	body := frame.Encode(frame.Hello, 0, []byte{1})
	first, err := manager.Create(ticket, "192.0.2.2", body)
	if err != nil {
		t.Fatal(err)
	}
	again, err := manager.Create(ticket, "192.0.2.2", body)
	if err != nil || again.Token != first.Token {
		t.Fatal("identical HELLO did not replay the session")
	}
	return first
}

func TestConcurrentBootstrapAdmission(t *testing.T) {
	cfg := lifecycleConfig(config.CarrierHTTPS)
	cfg.Limits.MaxSessionsGlobal = 1
	manager := NewManager(cfg, [32]byte{5})
	t.Cleanup(manager.Shutdown)
	first := establish(t, manager, &cfg.Profiles[0])
	second, err := manager.IssueBootstrap(&cfg.Profiles[0], "192.0.2.3")
	if err != nil {
		t.Fatal(err)
	}
	hello := frame.Encode(frame.Hello, 0, []byte{1})
	if _, err := manager.Create(second, "192.0.2.3", hello); !errors.Is(err, ErrLimit) {
		t.Fatalf("quota result %v", err)
	}
	first.Session.Close()
	awaitState(t, func() bool { return manager.Capacity().Sessions == 0 })
	var requests sync.WaitGroup
	const count = 8
	answers := make(chan CreateResult, count)
	failures := make(chan error, count)
	for range count {
		requests.Go(func() {
			value, err := manager.Create(second, "192.0.2.3", hello)
			if err != nil {
				failures <- err
				return
			}
			answers <- value
		})
	}
	requests.Wait()
	close(answers)
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	var token string
	for item := range answers {
		if token == "" {
			token = item.Token
		}
		if item.Token != token {
			t.Fatal("concurrent retry created more than one session")
		}
	}
	if token == "" || manager.Capacity().Sessions != 1 {
		t.Fatal("no session was admitted")
	}
}

func TestReconnectGraceStartsWhenCarrierDetaches(t *testing.T) {
	const grace = time.Minute
	for _, mode := range []config.CarrierMode{
		config.CarrierHTTPS, config.CarrierHTTPSLanes, config.CarrierWebSocket, config.CarrierWebSocketLanes,
	} {
		t.Run(string(mode), func(t *testing.T) {
			cfg := lifecycleConfig(mode)
			cfg.Timeouts.ReconnectGrace = grace
			manager := NewManager(cfg, [32]byte{12})
			t.Cleanup(manager.Shutdown)
			created := establish(t, manager, &cfg.Profiles[0])
			s := created.Session
			var disconnect func()
			switch mode {
			case config.CarrierHTTPS, config.CarrierHTTPSLanes:
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				finished := make(chan error, 1)
				go func() {
					if mode == config.CarrierHTTPS {
						_, _, err := s.Poll(ctx, 0)
						finished <- err
					} else {
						_, _, _, err := s.PollLane(ctx, 0, 0)
						finished <- err
					}
				}()
				awaitState(t, func() bool {
					s.mu.Lock()
					defer s.mu.Unlock()
					if mode == config.CarrierHTTPS {
						return s.waiter != nil
					}
					return s.carrierLanes[0].waiter != nil
				})
				disconnect = func() {
					cancel()
					if err := <-finished; !errors.Is(err, context.Canceled) {
						t.Fatalf("canceled long poll returned %v", err)
					}
				}
			case config.CarrierWebSocket, config.CarrierWebSocketLanes:
				var id uint32
				if mode == config.CarrierWebSocketLanes {
					id = 1
				}
				if !s.ClaimWebSocket(id) {
					t.Fatal("WebSocket was not admitted")
				}
				disconnect = func() { s.EndWebSocket(id, true) }
			}
			manager.reap(time.Now().Add(2 * grace))
			if _, err := manager.Get(created.Token); err != nil {
				t.Fatal("reaper closed a session with an attached carrier")
			}
			disconnect()
			if mode != config.CarrierWebSocket {
				s.mu.Lock()
				deadline := s.lastActivity.Add(grace)
				s.mu.Unlock()
				manager.reap(deadline.Add(-time.Nanosecond))
				if _, err := manager.Get(created.Token); err != nil {
					t.Fatal("detached session was closed before its reconnect grace elapsed")
				}
				manager.reap(deadline)
			}
			if _, err := manager.Get(created.Token); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("closed session lookup returned %v", err)
			}
			awaitState(t, func() bool { return manager.Capacity() == (Capacity{}) })
		})
	}
}

func TestReconnectGraceStartsAfterHTTPTransfer(t *testing.T) {
	const grace = time.Minute
	for _, mode := range []config.CarrierMode{config.CarrierHTTPS, config.CarrierHTTPSLanes} {
		t.Run(string(mode), func(t *testing.T) {
			for _, transfer := range []string{"upload", "downlink write"} {
				t.Run(transfer, func(t *testing.T) {
					cfg := lifecycleConfig(mode)
					cfg.Timeouts.ReconnectGrace = grace
					manager := NewManager(cfg, [32]byte{12})
					t.Cleanup(manager.Shutdown)
					created := establish(t, manager, &cfg.Profiles[0])
					s := created.Session
					var finish func()
					if transfer == "upload" {
						id := uint32(0)
						if mode == config.CarrierHTTPSLanes {
							id = 1
						}
						upload, err := s.BeginHTTPUpload(id, 1)
						if err != nil {
							t.Fatal(err)
						}
						finish = upload.Release
					} else {
						s.mu.Lock()
						queued := s.queueFrameLocked(frame.Ping, 0, nil)
						s.mu.Unlock()
						if !queued {
							t.Fatal("could not queue downlink")
						}
						var batch *Downlink
						var err error
						if mode == config.CarrierHTTPSLanes {
							batch, _, _, err = s.PollLane(t.Context(), 0, 0)
						} else {
							batch, _, err = s.Poll(t.Context(), 0)
						}
						if err != nil || batch == nil {
							t.Fatalf("could not borrow downlink: %v", err)
						}
						defer batch.Release()
						finish = batch.Release
					}
					s.mu.Lock()
					s.lastActivity = time.Now().Add(-2 * grace)
					s.mu.Unlock()
					manager.reap(time.Now())
					if _, err := manager.Get(created.Token); err != nil {
						t.Fatal("reaper closed a session during an HTTP transfer")
					}
					endedAfter := time.Now()
					finish()
					s.mu.Lock()
					ended := s.lastActivity
					s.mu.Unlock()
					if ended.Before(endedAfter) {
						t.Fatal("transfer completion did not start the reconnect grace")
					}
					manager.reap(ended.Add(grace - time.Nanosecond))
					if _, err := manager.Get(created.Token); err != nil {
						t.Fatal("session expired before the reconnect grace elapsed")
					}
					manager.reap(ended.Add(grace))
					if _, err := manager.Get(created.Token); !errors.Is(err, ErrAuthentication) {
						t.Fatalf("expired session lookup returned %v", err)
					}
					awaitState(t, func() bool { return manager.Capacity() == (Capacity{}) })
				})
			}
		})
	}
}

func TestUplinkSequenceRetriesAreHTTPOnly(t *testing.T) {
	for _, mode := range []config.CarrierMode{config.CarrierHTTPS, config.CarrierHTTPSLanes, config.CarrierWebSocket} {
		t.Run(string(mode), func(t *testing.T) {
			cfg := lifecycleConfig(mode)
			manager := NewManager(cfg, [32]byte{19})
			t.Cleanup(manager.Shutdown)
			s := establish(t, manager, &cfg.Profiles[0]).Session
			body := frame.Encode(frame.Pong, 0, []byte{4})
			send := func(sequence uint64, body []byte) (uint64, error) {
				request, err := s.BeginHTTPUpload(0, sequence)
				if err != nil {
					return 0, err
				}
				defer request.Release()
				return request.Submit(body)
			}
			if mode == config.CarrierWebSocket {
				send = func(sequence uint64, body []byte) (uint64, error) {
					return s.ProcessWebSocket(t.Context(), 0, sequence, body)
				}
			}
			if ack, err := send(1, body); ack != 1 || err != nil {
				t.Fatalf("initial uplink returned %d, %v", ack, err)
			}
			if mode != config.CarrierWebSocket {
				if ack, err := send(1, body); ack != 1 || err != nil {
					t.Fatalf("identical HTTP retry returned %d, %v", ack, err)
				}
				body[frame.HeaderSize]++
			}
			if _, err := send(1, body); !errors.Is(err, ErrProtocol) {
				t.Fatalf("invalid duplicate returned %v", err)
			}
		})
	}
}

func TestLaneReplayAndCloseOwnership(t *testing.T) {
	cfg := lifecycleConfig(config.CarrierHTTPSLanes)
	cfg.Limits.MaxClosedStreamIDs = 1
	connections := make(chan net.Conn, 2)
	cfg.Profiles[0].DialBackend = func(_ context.Context, ready func(error)) (net.Conn, error) {
		local, peer := net.Pipe()
		connections <- peer
		ready(nil)
		return local, nil
	}
	manager := NewManager(cfg, [32]byte{77})
	t.Cleanup(manager.Shutdown)
	s := establish(t, manager, &cfg.Profiles[0]).Session
	send := func(id uint32, sequence uint64, body []byte) (uint64, error) {
		upload, err := s.BeginHTTPUpload(id, sequence)
		if err != nil {
			return 0, err
		}
		defer upload.Release()
		return upload.Submit(body)
	}
	const first, second = 4, 7
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	for _, id := range []uint32{first, second} {
		open := frame.Encode(frame.Open, id, nil)
		for range 2 {
			if ack, err := send(id, 1, open); err != nil || ack != 1 {
				t.Fatalf("open %d resulted in %d, %v", id, ack, err)
			}
		}
	}
	for range 2 {
		select {
		case peer := <-connections:
			t.Cleanup(func() { _ = peer.Close() })
		case <-ctx.Done():
			t.Fatal("streams were not started")
		}
	}
	closed := frame.Encode(frame.Close, first, nil)
	if _, err := send(first, 2, closed); err != nil {
		t.Fatal(err)
	}
	if ack, err := send(first, 2, closed); ack != 2 || err != nil {
		t.Fatalf("close replay %d, %v", ack, err)
	}
	if _, _, ended, err := s.PollLane(ctx, first, 0); !ended || err != nil {
		t.Fatalf("lane did not terminate: %v", err)
	}
	if _, err := send(second, 2, frame.Encode(frame.Window, second, frame.WindowPayload(1))); err != nil {
		t.Fatal(err)
	}
	retry, err := s.BeginHTTPUpload(first, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer retry.Release()
	if !retry.replay {
		t.Fatal("closed lane was evicted before starting the retry")
	}
	if _, err := send(second, 3, frame.Encode(frame.Close, second, nil)); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	evicted := s.carrierLanes[first] == nil
	s.mu.Unlock()
	if !evicted {
		t.Fatal("closing the second lane did not evict the replay state")
	}
	if ack, err := retry.Submit(closed); ack != 2 || err != nil {
		t.Fatalf("retry after lane eviction returned %d, %v", ack, err)
	}
}

func TestDownlinkSupersessionAndReplay(t *testing.T) {
	cfg := lifecycleConfig(config.CarrierHTTPS)
	s := newSession(sessionOptions{profile: &cfg.Profiles[0], limits: cfg.Limits, timeouts: cfg.Timeouts})
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	type polled struct {
		item   *Downlink
		cursor uint64
		err    error
	}
	start := func() <-chan polled {
		reply := make(chan polled, 1)
		go func() { value, cursor, err := s.Poll(ctx, 0); reply <- polled{value, cursor, err} }()
		return reply
	}
	first := start()
	awaitState(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.waiter != nil })
	second := start()
	out := <-first
	if out.item != nil || out.err != nil || out.cursor != 0 {
		t.Fatalf("superseded poll returned %+v", out)
	}
	s.mu.Lock()
	queued := s.queueFrameLocked(frame.Data, 1, []byte("one response"))
	s.mu.Unlock()
	if !queued {
		t.Fatal("downlink queue rejected data")
	}
	out = <-second
	if out.err != nil || out.item == nil || out.cursor != 1 {
		t.Fatalf("downlink returned %+v", out)
	}
	want := readDownlink(t, out.item)
	again, cursor, err := s.Poll(ctx, 0)
	if err != nil || again == nil {
		t.Fatalf("downlink replay: %v", err)
	}
	defer again.Release()
	var retry bytes.Buffer
	if _, err := again.WriteTo(&retry); err != nil || cursor != 1 || !bytes.Equal(want, retry.Bytes()) {
		t.Fatal("cursor replay changed the response")
	}
	s.Close()
	if s.pendingCost == 0 {
		t.Fatal("session released borrowed downlink early")
	}
	again.Release()
	if s.pendingCost != 0 {
		t.Fatal("borrowed downlink charge leaked")
	}
}

func TestInvalidBatchDoesNotStartBackend(t *testing.T) {
	cfg := lifecycleConfig(config.CarrierHTTPS)
	manager := NewManager(cfg, [32]byte{4})
	t.Cleanup(manager.Shutdown)
	s := establish(t, manager, &cfg.Profiles[0]).Session
	body := append(frame.Encode(frame.Open, 17, nil), frame.Encode(frame.Data, 19, []byte{9})...)
	_, err := s.ProcessUp(1, body)
	if opened := manager.Metrics().StreamsOpened; !errors.Is(err, ErrProtocol) || opened != 0 {
		t.Fatalf("invalid batch started %d streams: %v", opened, err)
	}
}

func TestWebSocketBadCursorLeavesOtherLaneUsable(t *testing.T) {
	cfg := lifecycleConfig(config.CarrierWebSocketLanes)
	s := newSession(sessionOptions{profile: &cfg.Profiles[0], limits: cfg.Limits, timeouts: cfg.Timeouts})
	t.Cleanup(s.Close)
	const bad, good = 19, 21
	if !s.ClaimWebSocket(bad) || !s.ClaimWebSocket(good) {
		t.Fatal("failed to acquire the test lanes")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if _, _, _, err := s.PollLane(ctx, bad, 1); !errors.Is(err, ErrProtocol) {
		t.Fatalf("invalid cursor: %v", err)
	}
	if s.ClaimWebSocket(bad) {
		t.Fatal("invalid lane was reused before its carrier exited")
	}
	s.mu.Lock()
	queued := s.queueFrameLocked(frame.Close, good, nil)
	s.mu.Unlock()
	if !queued {
		t.Fatal("the other lane stopped accepting downlink frames")
	}
	batch, cursor, ended, err := s.PollLane(ctx, good, 0)
	if err != nil || ended || cursor != 1 || batch == nil {
		t.Fatalf("other lane poll: cursor %d, ended %t, %v", cursor, ended, err)
	}
	batch.Release()
	s.EndWebSocket(bad, true)
	if !s.ClaimWebSocket(bad) {
		t.Fatal("the unused lane stayed reserved after carrier exit")
	}
}
