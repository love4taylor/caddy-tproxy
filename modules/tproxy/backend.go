package tproxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

type backend struct {
	ctx    context.Context
	cancel context.CancelFunc
	log    *zap.Logger

	publicIP    netip.Addr
	dialer      net.Dialer
	routes      atomic.Pointer[routingConfig]
	routesReady chan struct{}
	next        atomic.Uint64
	streamID    atomic.Uint64
	mu          sync.Mutex
	wg          sync.WaitGroup
	poolMu      sync.Mutex
	pools       map[middleTarget]*middlePool
	poolChanged chan struct{}
	warmSignal  chan struct{}
	dialing     int
	sockets     int
	maxDials    int
	buffer      bufferBudget
	stats       backendStats
}

func newBackend(ctx caddy.Context, publicIP netip.Addr, log *zap.Logger) *backend {
	lifetime, cancel := context.WithCancel(ctx)
	return &backend{
		ctx: lifetime, cancel: cancel, log: log,
		publicIP: publicIP, dialer: net.Dialer{Timeout: 4 * time.Second},
		routesReady: make(chan struct{}), warmSignal: make(chan struct{}, 1),
	}
}

func (b *backend) start(ctx caddy.Context) {
	b.wg.Go(b.maintainMiddle)
	b.wg.Go(func() {
		b.refreshLoop(ctx.Storage(), &http.Client{
			Timeout:       12 * time.Second,
			CheckRedirect: checkRoutingRedirect,
		})
	})
}

func (b *backend) close() {
	b.mu.Lock()
	b.cancel()
	b.mu.Unlock()
	b.wg.Wait()
}

func (b *backend) dial(ctx context.Context, secret [16]byte, replays *handshakeReplays, ready func(error)) (net.Conn, error) {
	if b.routes.Load() == nil {
		wait, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		select {
		case <-b.routesReady:
		case <-b.ctx.Done():
			return nil, net.ErrClosed
		case <-wait.Done():
			return nil, wait.Err()
		}
	}
	if b.routes.Load() == nil {
		return nil, errors.New("MTProxy route configuration is unavailable")
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.ctx.Err(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	relay, client := newProxyPipe()
	b.wg.Go(func() {
		defer client.Close()
		streamCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		stopShutdown := context.AfterFunc(b.ctx, cancel)
		defer stopShutdown()
		stop := context.AfterFunc(streamCtx, func() { _ = client.Close() })
		defer stop()
		if err := b.serve(streamCtx, client, secret, replays, ready); err != nil && streamCtx.Err() == nil {
			b.log.Debug("MTProxy stream closed", zap.Error(err))
		}
	})
	return relay, nil
}

func (b *backend) serve(ctx context.Context, conn *proxyPipe, secret [16]byte, replays *handshakeReplays, ready func(error)) (err error) {
	defer func() {
		if ready != nil {
			ready(err)
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	client, err := acceptObfuscated(conn, secret, replays)
	if err != nil {
		if err == errHandshakeReplay {
			b.stats.handshakesRejected.Add(1)
		}
		return err
	}
	var first transportPacket
	var quickAck bool
	for {
		first, quickAck, err = client.readPacket(&b.buffer)
		if err != nil {
			return err
		}
		ping := client.pingPayload(first.payload())
		if ping == nil {
			break
		}
		// Transport PING is answered locally and needs no upstream stream.
		le.PutUint32(ping, rpcPong)
		err = client.writer.writePacket(client.tag, ping)
		first.release()
		if err != nil {
			return err
		}
	}
	if _, err := checkMTProtoPacket(first.payload()); err != nil {
		first.release()
		return err
	}
	if ready != nil {
		ready(nil)
		ready = nil
	}
	middleCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	stream, err := b.acquireMiddle(middleCtx, client.dc, conn)
	cancel()
	if err != nil {
		first.release()
		return err
	}
	_ = conn.SetDeadline(time.Time{})
	return forward(conn, &client, stream, first, quickAck)
}

func (b *backend) dialMiddle(ctx context.Context, target middleTarget) (*middleConn, error) {
	// Give other endpoints time to answer if the first TCP or RPC handshake stalls.
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := b.dialer.DialContext(ctx, "tcp4", target.address.String())
	if err != nil {
		return nil, err
	}
	end, _ := ctx.Deadline()
	_ = conn.SetDeadline(end)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	middle, err := negotiateMiddle(conn, target.secret, b.publicIP)
	stopped := stop()
	if err == nil && !stopped {
		err = ctx.Err()
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	b.log.Debug("connected to Telegram data center", zap.Stringer("address", target.address))
	return middle, nil
}
