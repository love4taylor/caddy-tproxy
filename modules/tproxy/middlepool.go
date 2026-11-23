package tproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

const (
	// The official proxy caps each target at eight RPC connections.
	maxMiddleConnections = 8
	streamsBeforeGrowth  = 16
	middleIdleTimeout    = 2 * time.Minute
	middleRetryDelay     = time.Second
	middleMaxRetryDelay  = 30 * time.Second
	maxMiddleSockets     = 128
	maxWarmSockets       = 24
	defaultMiddleDials   = 8
	middlePingInterval   = 5 * time.Second
	middleReadTimeout    = 20 * middlePingInterval

	maxMiddleStreamPackets = 32
	maxMiddleStreamBytes   = 4 << 20
)

type middleTarget struct {
	address netip.AddrPort
	secret  [128]byte
}

// The backend's pool lock protects connection selection and dial reservations.
type middlePool struct {
	connections []*middleConn
	dialCancel  context.CancelFunc
	retryAfter  time.Time
	retryDelay  time.Duration
}

func (b *backend) acquireMiddle(ctx context.Context, dc int16, client net.Conn) (*middleStream, error) {
	order := b.next.Add(1) - 1
	start := time.Now()
	defer func() { b.stats.poolWait.Observe(time.Since(start)) }()
	var retry *time.Timer
	for ctx.Err() == nil && b.ctx.Err() == nil {
		b.poolMu.Lock()
		routes := b.routes.Load()
		if routes == nil {
			b.poolMu.Unlock()
			return nil, errors.New("MTProxy route configuration is unavailable")
		}
		targets := routes.targets(dc)
		if len(targets) == 0 {
			b.poolMu.Unlock()
			return nil, fmt.Errorf("no Telegram endpoint for DC %d", dc)
		}
		offset := int(order % uint64(len(targets)))
		best, load, candidate, retryAt := b.chooseMiddle(routes.secret, targets, offset, time.Now())
		if candidate.address.IsValid() && (best == nil || load >= streamsBeforeGrowth) {
			b.scheduleMiddle(candidate)
		}
		if best != nil {
			stream := best.attach(b.streamID.Add(1), client)
			b.poolMu.Unlock()
			if stream != nil {
				return stream, nil
			}
			continue
		}
		wait := b.poolSignal()
		b.poolMu.Unlock()
		// Dial completion, socket retirement and route updates signal the
		// pool. Only a target's backoff can expire without a notification.
		var retryC <-chan time.Time
		if !retryAt.IsZero() {
			delay := time.Until(retryAt)
			if retry == nil {
				retry = time.NewTimer(delay)
			} else {
				retry.Reset(delay)
			}
			retryC = retry.C
		}
		select {
		case <-wait:
		case <-retryC:
		case <-ctx.Done():
		case <-b.ctx.Done():
		}
		if retryC != nil {
			retry.Stop()
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, net.ErrClosed
}

// All pool methods below, through scheduleMiddle, run under poolMu.
func (b *backend) poolSignal() <-chan struct{} {
	if b.poolChanged == nil {
		b.poolChanged = make(chan struct{})
	}
	return b.poolChanged
}

func (b *backend) signalPool() {
	if b.poolChanged != nil {
		close(b.poolChanged)
		b.poolChanged = nil
	}
}

func (b *backend) chooseMiddle(secret [128]byte, targets []netip.AddrPort, offset int, now time.Time) (*middleConn, int, middleTarget, time.Time) {
	var best *middleConn
	load := math.MaxInt
	var candidate middleTarget
	var retryAt time.Time
	for i := range targets {
		key := middleTarget{address: targets[(i+offset)%len(targets)], secret: secret}
		pool := b.pools[key]
		open := 0
		if pool != nil {
			for _, conn := range pool.connections {
				if n, ready := conn.load(); ready {
					open++
					if n < load {
						best, load = conn, n
					}
				}
			}
			if open >= maxMiddleConnections || pool.dialCancel != nil {
				continue
			}
			if now.Before(pool.retryAfter) {
				if retryAt.IsZero() || pool.retryAfter.Before(retryAt) {
					retryAt = pool.retryAfter
				}
				continue
			}
		}
		if !candidate.address.IsValid() {
			candidate = key
		}
	}
	return best, load, candidate, retryAt
}

func (b *backend) scheduleMiddle(target middleTarget) {
	maxDials := b.maxDials
	if maxDials == 0 {
		maxDials = defaultMiddleDials
	}
	if b.dialing >= maxDials || b.sockets+b.dialing >= maxMiddleSockets {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ctx.Err() != nil {
		return
	}
	if b.pools == nil {
		b.pools = make(map[middleTarget]*middlePool)
	}
	pool := b.pools[target]
	if pool == nil {
		pool = new(middlePool)
		b.pools[target] = pool
	}
	ctx, cancel := context.WithCancel(b.ctx)
	pool.dialCancel = cancel
	b.dialing++
	b.stats.dials.Add(1)
	b.wg.Go(func() { b.connectMiddle(ctx, target, pool) })
}

func (b *backend) connectMiddle(ctx context.Context, target middleTarget, pool *middlePool) {
	start := time.Now()
	middle, err := b.dialMiddle(ctx, target)
	b.stats.dialTime.Observe(time.Since(start))
	b.poolMu.Lock()
	canceled := ctx.Err() != nil
	pool.dialCancel()
	pool.dialCancel = nil
	b.dialing--
	b.signalPool()
	if routes := b.routes.Load(); canceled || routes == nil || !routes.contains(target) {
		b.poolMu.Unlock()
		if middle != nil {
			_ = middle.conn.Close()
		}
		b.wakeMiddle()
		return
	}
	if err != nil {
		if b.ctx.Err() == nil {
			b.stats.dialFailures.Add(1)
			pool.backoff()
			b.log.Debug("Telegram RPC dial failed", zap.Error(err))
		}
		b.poolMu.Unlock()
		return
	}
	pool.retryAfter, pool.retryDelay = time.Time{}, 0
	middle.done = make(chan struct{})
	middle.writes = make(chan *middleWrite, middleWriteQueue)
	middle.streams = make(map[uint64]*middleStream)
	middle.idleSince = time.Now()
	middle.budget = &b.buffer
	middle.stats = &b.stats
	pool.connections = append(pool.connections, middle)
	b.sockets++
	b.stats.sockets.Add(1)
	b.poolMu.Unlock()
	b.wakeMiddle()
	b.runMiddle(pool, middle)
}

func (p *middlePool) backoff() {
	p.retryDelay = min(middleMaxRetryDelay, max(middleRetryDelay, p.retryDelay*2))
	p.retryAfter = time.Now().Add(p.retryDelay + rand.N(time.Second/4))
}

func (b *backend) maintainMiddle() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var routes *routingConfig
	var dcs []int
	for b.ctx.Err() == nil {
		if latest := b.routes.Load(); routes != latest {
			routes = latest
			dcs = dcs[:0]
			if routes != nil {
				for dc := range routes.dcs {
					dcs = append(dcs, int(dc))
				}
				sort.Ints(dcs)
			}
		}
		if routes != nil {
			b.keepMiddleWarm(routes, dcs)
		}
		select {
		case <-ticker.C:
		case <-b.warmSignal:
		case <-b.ctx.Done():
		}
	}
}

func (b *backend) wakeMiddle() {
	select {
	case b.warmSignal <- struct{}{}:
	default:
	}
}

func (b *backend) publishRoutes(routes *routingConfig) {
	current := make(map[netip.AddrPort]bool)
	for _, targets := range routes.dcs {
		for _, address := range targets {
			current[address] = true
		}
	}
	b.poolMu.Lock()
	for target, pool := range b.pools {
		if target.secret == routes.secret && current[target.address] {
			continue
		}
		// In-flight workers keep their pool until they finish. A target that
		// returns in a later update must start with a fresh pool and backoff.
		delete(b.pools, target)
		if pool.dialCancel != nil {
			pool.dialCancel()
		}
		for _, conn := range pool.connections {
			conn.streamMu.Lock()
			conn.warm, conn.retired = false, true
			if len(conn.streams) == 0 {
				conn.closeLocked()
			}
			conn.streamMu.Unlock()
		}
	}
	// Selection and publication share the lock. Existing streams can drain,
	// but a removed target cannot gain another stream after the update.
	if previous := b.routes.Swap(routes); previous == nil && b.routesReady != nil {
		close(b.routesReady)
	}
	b.signalPool()
	b.poolMu.Unlock()
	b.wakeMiddle()
}

func (b *backend) keepMiddleWarm(routes *routingConfig, dcs []int) {
	b.poolMu.Lock()
	defer b.poolMu.Unlock()
	if b.routes.Load() != routes {
		return
	}
	now := time.Now()
	warm := make(map[*middleConn]struct{}, min(len(dcs), maxWarmSockets))
	for _, dc := range dcs[:min(len(dcs), maxWarmSockets)] {
		best, _, candidate, _ := b.chooseMiddle(routes.secret, routes.dcs[int16(dc)], 0, now)
		if best != nil {
			warm[best] = struct{}{}
		} else if candidate.address.IsValid() {
			b.scheduleMiddle(candidate)
		}
	}
	for target, pool := range b.pools {
		for _, conn := range pool.connections {
			conn.streamMu.Lock()
			_, conn.warm = warm[conn]
			conn.streamMu.Unlock()
		}
		if len(pool.connections) == 0 && pool.dialCancel == nil && !now.Before(pool.retryAfter.Add(time.Minute)) {
			delete(b.pools, target)
		}
	}
}

func (b *backend) runMiddle(pool *middlePool, conn *middleConn) {
	stop := context.AfterFunc(b.ctx, conn.close)
	defer stop()
	var workers sync.WaitGroup
	workers.Go(conn.heartbeat)
	workers.Go(conn.writeStreams)
	err := conn.readStreams()
	conn.close()
	workers.Wait()
	unexpected := !errors.Is(err, net.ErrClosed)
	if conn.writeErr != nil {
		if !unexpected {
			err = conn.writeErr
		}
		unexpected = true
	}
	b.poolMu.Lock()
	for i, current := range pool.connections {
		if current == conn {
			last := len(pool.connections) - 1
			pool.connections[i] = pool.connections[last]
			pool.connections[last] = nil
			pool.connections = pool.connections[:last]
			break
		}
	}
	if unexpected && b.ctx.Err() == nil {
		pool.backoff()
		b.stats.disconnects.Add(1)
	}
	b.sockets--
	b.stats.sockets.Add(-1)
	b.wakeMiddle()
	b.signalPool()
	b.poolMu.Unlock()
	if b.ctx.Err() == nil && unexpected && !errors.Is(err, io.EOF) {
		b.log.Debug("Telegram RPC connection closed", zap.Error(err))
	}
}

type middleStream struct {
	id       uint64
	middle   *middleConn
	client   net.Conn
	packets  chan middlePacket
	pending  atomic.Int64
	detached atomic.Bool
	// Protected by the owning connection's stream lock.
	remoteClosed    bool
	downlinkAborted bool
	writeResult     chan error
}

type middlePacket struct {
	frame ownedBuffer
	ack   uint32 // Used for packets without a frame.
}

func (m *middleConn) load() (int, bool) {
	m.streamMu.Lock()
	defer m.streamMu.Unlock()
	return len(m.streams), !m.closed && !m.retired
}

func (m *middleConn) attach(id uint64, client net.Conn) *middleStream {
	m.streamMu.Lock()
	defer m.streamMu.Unlock()
	if m.closed || m.retired {
		return nil
	}
	s := &middleStream{
		id: id, middle: m, client: client,
		packets: make(chan middlePacket, maxMiddleStreamPackets), writeResult: make(chan error, 1),
	}
	m.streams[id] = s
	return s
}

func (m *middleConn) detachLocked(s *middleStream) {
	s.detached.Store(true)
	delete(m.streams, s.id)
	close(s.packets)
	if len(m.streams) == 0 && !m.closed {
		if m.retired {
			m.closeLocked()
		} else {
			m.idleSince = time.Now()
		}
	}
}

func (s *middleStream) finish(sent bool) {
	m := s.middle
	m.streamMu.Lock()
	if m.streams[s.id] == s {
		m.detachLocked(s)
	}
	notify := sent && !s.remoteClosed && !m.closed
	discard := !s.downlinkAborted
	m.streamMu.Unlock()
	if discard {
		s.discardDownlink()
	}
	if notify {
		_ = m.notifyClosed(s.id)
	}
}

// Called after detaching the stream. A packet already taken by the client
// writer stays with that writer until its write returns.
func (s *middleStream) discardDownlink() {
	for packet := range s.packets {
		s.release(packet)
	}
}

func (s *middleStream) release(packet middlePacket) {
	if packet.frame.data != nil {
		s.pending.Add(-int64(cap(packet.frame.data)))
		packet.frame.release()
	}
}

func (s *middleStream) send(request *middleWrite, prefix []byte, packet transportPacket, stop <-chan struct{}) error {
	request.prefix, request.body, request.result, request.stream = prefix, packet.payload(), s.writeResult, s
	request.stop = stop
	request.wire = nil
	if packet.offset == rpcFrameHeader+len(prefix) && cap(packet.data) >= rpcPaddedSize(rpcFrameSize(prefix, request.body)) {
		request.wire = packet.data[:0]
	}
	err := s.middle.queueWrite(request)
	if err == nil {
		// Once admitted, keep the packet alive until the writer releases it.
		err = <-s.writeResult
	}
	// The writer has finished borrowing the packet. An idle stream must
	// not retain the backing allocation through its reusable request.
	request.body, request.wire = nil, nil
	return err
}

func (m *middleConn) dispatch(id uint64, packet middlePacket) {
	m.streamMu.Lock()
	s := m.streams[id]
	cost := int64(cap(packet.frame.data))
	if s != nil && len(s.packets) < cap(s.packets) && s.pending.Load()+cost <= maxMiddleStreamBytes {
		if cost != 0 {
			s.pending.Add(cost)
		}
		s.packets <- packet
		m.streamMu.Unlock()
		return
	}
	m.streamMu.Unlock()
	packet.frame.release()
	m.dropStream(id)
}

func (m *middleConn) dropStream(id uint64) {
	m.streamMu.Lock()
	s := m.streams[id]
	if s != nil {
		// The reader drains the queue before processing the next RPC frame.
		s.downlinkAborted = true
		m.detachLocked(s)
	}
	m.streamMu.Unlock()
	if s != nil {
		m.stats.slowStreams.Add(1)
		// Only the affected client should be interrupted on queue pressure.
		_ = s.client.Close()
		s.discardDownlink()
		return
	}
	_ = m.notifyClosed(id)
}

func (m *middleConn) notifyClosed(id uint64) error {
	return m.sendControl(rpcCloseConn, id)
}

func (m *middleConn) close() {
	m.streamMu.Lock()
	defer m.streamMu.Unlock()
	m.closeLocked()
}

func (m *middleConn) closeLocked() {
	if !m.closed {
		m.closed = true
		for _, stream := range m.streams {
			m.detachLocked(stream)
		}
		m.writeMu.Lock()
		close(m.done)
		close(m.writes)
		m.writeMu.Unlock()
		_ = m.conn.Close()
	}
}

func (m *middleConn) heartbeat() {
	tick := time.NewTicker(middlePingInterval)
	defer tick.Stop()
	for {
		select {
		case <-m.done:
			return
		case now := <-tick.C:
			m.streamMu.Lock()
			if len(m.streams) == 0 && !m.warm && now.Sub(m.idleSince) >= middleIdleTimeout {
				m.closeLocked()
			}
			closed := m.closed
			m.streamMu.Unlock()
			if closed {
				return
			}
			_ = m.sendControl(rpcPing, uint64(now.UnixNano()))
		}
	}
}

func (m *middleConn) readStreams() error {
	for {
		m.readSource.armDeadline = true
		frame, prefix, err := m.readFrame(m.budget, maxRPCPacket)
		if err != nil {
			return err
		}
		packet, size := prefix.body, prefix.size
		if frame.data != nil {
			frame.data = frame.data[:len(frame.data)-4]
			packet = frame.data[8:]
			size = len(packet)
		}
		switch le.Uint32(packet) {
		case rpcProxyAns:
			if size >= rpcProxyAnswerHeader+4 {
				id := le.Uint64(packet[8:])
				if frame.data == nil {
					m.dropStream(id)
				} else {
					m.dispatch(id, middlePacket{frame: frame})
				}
				continue
			}
		case rpcSimpleAck:
			if size == rpcSimpleAckBody {
				m.dispatch(le.Uint64(packet[4:]), middlePacket{ack: le.Uint32(packet[12:])})
			}
		case rpcCloseExt, rpcPing:
			if size == rpcControlBody {
				m.handleControl(packet)
			}
		}
		frame.release()
	}
}

func (m *middleConn) handleControl(packet []byte) {
	id := le.Uint64(packet[4:])
	if le.Uint32(packet) == rpcPing {
		_ = m.sendControl(rpcPong, id)
		return
	}
	m.streamMu.Lock()
	if s := m.streams[id]; s != nil {
		s.remoteClosed = true
		m.detachLocked(s)
	}
	m.streamMu.Unlock()
}
