package session

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/love4taylor/caddy-tproxy/internal/config"
	"github.com/love4taylor/caddy-tproxy/internal/frame"
)

func TestEvictedTombstoneDoesNotPermitStreamReuse(t *testing.T) {
	for _, mode := range []config.CarrierMode{config.CarrierHTTPS, config.CarrierHTTPSLanes, config.CarrierWebSocketLanes} {
		t.Run(string(mode), func(t *testing.T) {
			settings := config.Defaults()
			settings.Limits.MaxClosedStreamIDs = 1
			profile := config.Profile{CarrierMode: mode, DialBackend: func(ctx context.Context, _ func(error)) (net.Conn, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}}
			s := newSession(sessionOptions{profile: &profile, limits: settings.Limits, timeouts: settings.Timeouts})
			t.Cleanup(func() { s.Close(); s.backendWG.Wait() })
			var sequence uint64
			send := func(seq uint64, kind frame.Type, id uint32) error {
				wire := frame.Encode(kind, id, nil)
				if mode == config.CarrierHTTPS {
					sequence++
					_, err := s.ProcessUp(sequence, wire)
					return err
				}
				_, err := s.ProcessUpLane(id, seq, wire)
				return err
			}
			for _, id := range []uint32{4095, frame.MaxStreamID} {
				if err := send(1, frame.Open, id); err != nil {
					t.Fatal(err)
				}
				if err := send(2, frame.Close, id); err != nil {
					t.Fatal(err)
				}
			}
			if mode == config.CarrierWebSocketLanes {
				if s.ClaimWebSocket(4095) {
					t.Fatal("a socket reattached to an evicted stream")
				}
				return
			}
			if mode == config.CarrierHTTPSLanes {
				const cursor = 1
				batch, next, closed, err := s.PollLane(t.Context(), 4095, cursor)
				if batch != nil || next != cursor || !closed || err != nil {
					t.Fatalf("poll on retired lane returned batch %t, cursor %d, closed %t, error %v",
						batch != nil, next, closed, err)
				}
				if _, _, _, err := s.PollLane(t.Context(), 4096, cursor); !errors.Is(err, ErrProtocol) {
					t.Fatalf("poll on unopened lane returned %v", err)
				}
			}
			if err := send(1, frame.Open, 4095); !errors.Is(err, ErrProtocol) {
				t.Fatalf("an evicted stream accepted OPEN: %v", err)
			}
		})
	}
}
