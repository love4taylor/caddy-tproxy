package session

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math"
	"sync"
	"time"

	"github.com/love4taylor/caddy-tproxy/internal/config"
	"github.com/love4taylor/caddy-tproxy/internal/frame"
)

const (
	queueItemCost                = 256
	controlReserveExtraItems     = 16
	controlReserveItemsPerStream = 3
)

type pendingClass byte

const (
	pendingUplink pendingClass = iota
	pendingDownlink
	pendingControl
)

type sessionOptions struct {
	profile  *config.Profile
	manager  *Manager
	quota    *profileQuota
	limits   config.Limits
	timeouts config.Timeouts
}

type streamState struct {
	backend       *backendStream
	receiveWindow uint32
	writesTrimmed bool // The slice may still retain storage for previous writes.
	sendCredit    uint64
	creditNotify  chan struct{}

	uncreditedBytes int
	queuedWriteCost int
	activeWriteCost int
	writes          [][]byte
	writeNotify     chan struct{}
}

type downBatch struct {
	body    frame.BatchBuffer
	parts   [][]byte
	size    int
	cost    int
	items   int
	writing bool
	retired bool
}

// Downlink holds a batch's budget until the carrier has finished writing it.
type Downlink struct {
	session *Session
	queue   *downQueue
	batch   *downBatch
}

// WebSocketMessage returns the contiguous message, if available. Use WriteTo
// for a batch that spans multiple buffers. Both borrows end at Release.
func (d *Downlink) WebSocketMessage() []byte { return d.batch.body.Bytes }

func (d *Downlink) Len() int { return d.batch.size }

func (d *Downlink) WriteTo(w io.Writer) (int64, error) {
	parts := d.batch.parts
	if len(parts) == 0 {
		parts = [][]byte{d.batch.body.Bytes}
	}
	var total int64
	for _, part := range parts {
		n, err := w.Write(part)
		total += int64(n)
		if err != nil {
			return total, err
		}
		if n != len(part) {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func (d *Downlink) Release() {
	s := d.session
	s.mu.Lock()
	defer s.mu.Unlock()
	if batch := d.batch; batch != nil {
		d.batch = nil
		batch.writing = false
		s.activeDownlinks--
		s.lastActivity = time.Now()
		if batch.retired {
			s.detachedCost -= batch.cost
			s.detachedItems -= batch.items
			s.releaseDownLocked(batch)
		} else if d.queue.waiter != nil {
			signal(d.queue.notify)
		}
	}
}

func (s *Session) borrowDownLocked(q *downQueue) *Downlink {
	batch := q.unacked
	batch.writing = true
	s.activeDownlinks++
	return &Downlink{session: s, queue: q, batch: batch}
}

func (s *Session) retireDownLocked(slot **downBatch) {
	batch := *slot
	if batch == nil {
		return
	}
	*slot = nil
	if batch.writing {
		batch.retired = true
		s.detachedCost += batch.cost
		s.detachedItems += batch.items
		return
	}
	s.releaseDownLocked(batch)
}

func (s *Session) releaseDownLocked(batch *downBatch) {
	if batch.items == 1 {
		// A single-frame body is the original queued buffer.
		recycleDownlinkFrame(batch.body.Bytes)
	}
	for _, part := range batch.parts {
		recycleDownlinkFrame(part)
	}
	batch.body.Recycle()
	batch.parts = nil
	s.releasePendingLocked(batch.cost, batch.items)
}

type downQueue struct {
	pendingFrames  [][]byte
	trimmedFrames  bool // The slice may still retain storage for previously packed frames.
	pendingWindows map[uint32]uint64
	pendingBase    uint64 // Position of the first pending frame.
	unacked        *downBatch
	downCursor     uint64
	waiter         chan struct{}
	notify         chan struct{}
}

func newDownQueue() downQueue {
	return downQueue{pendingWindows: make(map[uint32]uint64), notify: make(chan struct{}, 1)}
}

type carrierLane struct {
	downQueue
	lastUpSequence uint64
	lastUpDigest   [sha256.Size]byte
}

func newCarrierLane() *carrierLane { return &carrierLane{downQueue: newDownQueue()} }

type Session struct {
	sessionOptions
	downQueue
	carrier config.CarrierMode
	mu      sync.Mutex

	streams         map[uint32]*streamState
	closedStreams   map[uint32]struct{}
	closedOrder     []uint32
	closedStart     int
	usedStreamIDs   streamIDs
	pendingLimits   pendingLimits
	pendingCost     int
	pendingItems    int
	detachedCost    int
	detachedItems   int
	lastUpSequence  uint64
	lastUpDigest    [sha256.Size]byte
	upActive        bool
	httpUploading   bool
	httpLaneUploads map[uint32]struct{}
	websocketActive bool
	activePolls     int
	activeDownlinks int
	closed          bool
	lastActivity    time.Time
	budgetNotify    chan struct{}
	lifetime        context.Context
	cancel          context.CancelFunc
	carrierLanes    map[uint32]*carrierLane
	websocketLanes  map[uint32]struct{}
	backendWG       sync.WaitGroup
}

func newSession(options sessionOptions) *Session {
	lifetime, cancel := context.WithCancel(context.Background())
	result := &Session{
		sessionOptions: options,
		carrier:        options.profile.CarrierMode.WithDefault(),
		lastActivity:   time.Now(),
		lifetime:       lifetime,
		cancel:         cancel,
		pendingLimits:  sessionPendingLimits(options.limits),
		streams:        make(map[uint32]*streamState),
		closedStreams:  make(map[uint32]struct{}),
	}
	switch result.carrier {
	case config.CarrierHTTPSLanes:
		result.carrierLanes = map[uint32]*carrierLane{0: newCarrierLane()}
	case config.CarrierWebSocketLanes:
		result.carrierLanes = make(map[uint32]*carrierLane)
		result.websocketLanes = make(map[uint32]struct{})
	default:
		result.downQueue = newDownQueue()
	}
	return result
}

func (s *Session) CarrierMode() config.CarrierMode {
	return s.carrier
}

// OnClose interrupts a carrier even if it is blocked in network I/O.
func (s *Session) OnClose(interrupt func()) func() bool {
	return context.AfterFunc(s.lifetime, interrupt)
}

func (s *Session) usesCarrierLanes() bool {
	return s.carrier == config.CarrierHTTPSLanes || s.carrier == config.CarrierWebSocketLanes
}

// ClaimWebSocket reserves the carrier until the HTTP upgrade handler exits.
// In lane mode the reservation survives protocol errors and tombstone eviction.
func (s *Session) ClaimWebSocket(id uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	switch s.carrier {
	case config.CarrierWebSocket:
		if id == 0 && !s.websocketActive {
			s.websocketActive = true
			return true
		}
		return false
	case config.CarrierWebSocketLanes:
		if id == 0 || id > frame.MaxStreamID || len(s.websocketLanes) >= s.limits.MaxStreamsPerSession {
			return false
		}
	default:
		return false
	}
	_, active := s.websocketLanes[id]
	if active || s.usedStreamIDs.contains(id) {
		return false
	}
	s.websocketLanes[id] = struct{}{}
	if s.carrierLanes[id] == nil {
		s.carrierLanes[id] = newCarrierLane()
	}
	s.lastActivity = time.Now()
	return true
}

func (s *Session) EndWebSocket(id uint32, established bool) {
	if s.carrier == config.CarrierWebSocket {
		if established {
			s.Close()
		} else {
			s.mu.Lock()
			s.websocketActive = false
			s.mu.Unlock()
		}
		return
	}
	if s.carrier != config.CarrierWebSocketLanes {
		return
	}
	s.mu.Lock()
	delete(s.websocketLanes, id)
	retired := s.detachWebSocketLaneLocked(id)
	s.lastActivity = time.Now()
	s.mu.Unlock()
	if retired != nil {
		retired.close()
	}
}

func (s *Session) detachWebSocketLaneLocked(id uint32) *backendStream {
	lane, found := s.carrierLanes[id]
	if !found {
		return nil
	}
	delete(s.carrierLanes, id)
	s.releaseLaneLocked(lane)
	stream := s.streams[id]
	if stream == nil {
		return nil
	}
	s.dropStream(id, stream)
	return stream.backend
}

func (s *Session) Poll(ctx context.Context, cursor uint64) (*Downlink, uint64, error) {
	if s.usesCarrierLanes() {
		return nil, cursor, ErrProtocol
	}
	batch, next, _, err := s.poll(ctx, 0, cursor)
	return batch, next, err
}

func (s *Session) PollLane(ctx context.Context, id uint32, cursor uint64) (*Downlink, uint64, bool, error) {
	if !s.usesCarrierLanes() || id > frame.MaxStreamID {
		return nil, cursor, false, ErrProtocol
	}
	return s.poll(ctx, id, cursor)
}

func (s *Session) poll(ctx context.Context, id uint32, cursor uint64) (*Downlink, uint64, bool, error) {
	s.mu.Lock()
	var detached *backendStream
	defer func() {
		s.mu.Unlock()
		if detached != nil {
			detached.close()
		}
	}()
	if s.closed {
		return nil, cursor, false, ErrClosed
	}
	q := &s.downQueue
	var lane *carrierLane
	if s.usesCarrierLanes() {
		lane = s.carrierLanes[id]
		if lane == nil {
			// An HTTPS retry can arrive after the closed lane's replay state
			// was evicted. The stream ID is still retired for this session.
			if s.carrier == config.CarrierHTTPSLanes && s.usedStreamIDs.contains(id) {
				return nil, cursor, true, nil
			}
			return nil, cursor, false, ErrProtocol
		}
		q = &lane.downQueue
	}
	var parked chan struct{}
	defer func() {
		s.lastActivity = time.Now()
		if parked != nil {
			s.activePolls--
			if q.waiter == parked {
				q.waiter = nil
			}
		}
	}()
	replay := q.unacked != nil && cursor == q.downCursor-1
	if !replay {
		if cursor != q.downCursor || cursor == math.MaxUint64 {
			if s.carrier == config.CarrierWebSocketLanes {
				detached = s.detachWebSocketLaneLocked(id)
			} else {
				s.closeLocked()
			}
			return nil, cursor, false, ErrProtocol
		}
		s.retireDownLocked(&q.unacked)
	}
	if q.waiter != nil {
		close(q.waiter)
		q.waiter = nil
	}
	var timer *time.Timer
	var timedOut bool
	for {
		if parked != nil && q.waiter != parked {
			// The old waiter may have received the only notification.
			signal(q.notify)
			return nil, cursor, false, nil
		}
		if s.closed {
			return nil, cursor, false, ErrClosed
		}
		if replay && q.unacked != nil {
			// A retry can arrive before the old HTTP writer has noticed
			// the connection failure. Keep only the newest retry parked.
			if !q.unacked.writing {
				return s.borrowDownLocked(q), q.downCursor, false, nil
			}
		} else if len(q.pendingFrames) > 0 {
			batch := s.packDownlink(q)
			q.downCursor++
			q.unacked = &batch
			if s.manager != nil {
				s.manager.counters.down.Add(uint64(batch.size))
			}
			return s.borrowDownLocked(q), q.downCursor, false, nil
		} else if lane != nil && id != 0 {
			_, ended := s.closedStreams[id]
			if s.carrierLanes[id] != lane || (ended && s.streams[id] == nil) {
				return nil, cursor, true, nil
			}
		}
		if timedOut {
			return nil, cursor, false, nil
		}
		if parked == nil {
			parked = make(chan struct{})
			q.waiter = parked
			s.activePolls++
			timer = time.NewTimer(s.timeouts.LongPoll)
			defer timer.Stop()
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			s.mu.Lock()
			return nil, cursor, false, ctx.Err()
		case <-s.lifetime.Done():
			s.mu.Lock()
			return nil, cursor, false, ErrClosed
		case <-parked:
		case <-q.notify:
		case <-timer.C:
			timedOut = true
		}
		s.mu.Lock()
	}
}

func (s *Session) Close() {
	s.mu.Lock()
	s.closeLocked()
	s.mu.Unlock()
}

// planUplinkLocked checks each stream's state at that point in the batch and
// accounts backend writes before any frame mutates a live stream. Most batches
// touch one stream. Keep that state inline and look up other IDs only on demand.
func (s *Session) planUplinkLocked(values []frame.Frame) (bytes, items int, valid bool) {
	type state struct {
		remaining   uint32
		known, live bool
	}
	var currentID uint32
	var current state
	var other map[uint32]state
	var pages [64]uint64
	inlinePage := s.usedStreamIDs.hasFirst
	for i := 0; i < len(values); {
		value := values[i]
		i++
		id := value.StreamID
		if id == 0 {
			if value.Type != frame.Pong {
				return 0, 0, false
			}
			continue
		}
		if id != currentID {
			if currentID != 0 {
				if other == nil {
					other = make(map[uint32]state)
				}
				other[currentID] = current
			}
			currentID = id
			var found bool
			current, found = other[id]
			if !found {
				if stream := s.streams[id]; stream != nil {
					current = state{remaining: stream.receiveWindow, known: true, live: true}
				} else {
					_, current.known = s.closedStreams[id]
					current.known = current.known || s.usedStreamIDs.contains(id)
				}
			}
		}
		switch value.Type {
		case frame.Open:
			if current.known {
				return 0, 0, false
			}
			page := id >> 12
			bit := uint64(1) << (page & 63)
			if s.usedStreamIDs.page(uint16(page)) == nil && pages[page>>6]&bit == 0 {
				pages[page>>6] |= bit
				if inlinePage {
					if bytes > math.MaxInt-streamIDPageCost {
						return 0, 0, false
					}
					bytes += streamIDPageCost
				}
				inlinePage = true
			}
			current = state{remaining: frame.InitialStreamWindow, known: true, live: true}
		case frame.Data, frame.Window, frame.Close:
			if !current.known {
				return 0, 0, false
			}
			if !current.live {
				continue
			}
			if value.Type == frame.Close {
				current.live = false
			}
			if value.Type == frame.Data {
				var length int
				i, length = uplinkDataRun(values, i-1)
				if length > int(current.remaining) || length > math.MaxInt-queueItemCost-bytes {
					return 0, 0, false
				}
				current.remaining -= uint32(length)
				bytes += length + queueItemCost
				items++
			}
		default:
			return 0, 0, false
		}
	}
	return bytes, items, true
}

// Group consecutive DATA for one stream into a backend write. Admission and
// application use the same grouping, even if growing an old buffer fails.
func uplinkDataRun(frames []frame.Frame, first int) (end, size int) {
	id := frames[first].StreamID
	size = len(frames[first].Payload)
	for end = first + 1; end < len(frames) && size < frame.DataChunk; end++ {
		next := frames[end]
		if next.Type != frame.Data || next.StreamID != id || len(next.Payload) > frame.DataChunk-size {
			break
		}
		size += len(next.Payload)
	}
	return end, size
}

func (s *Session) applyBatchLocked(frames []frame.Frame, cost, items int) (
	started, stopped []*backendStream, remainingCost, remainingItems int, ok bool,
) {
	for i := 0; i < len(frames); {
		f := frames[i]
		i++
		id := f.StreamID
		if f.Type == frame.Open {
			if s.usedStreamIDs.add(id) {
				cost -= streamIDPageCost
			}
			stream := s.attachStream(id)
			if stream != nil {
				started = append(started, stream)
				continue
			}
			s.rememberClosedLocked(id)
			if s.manager != nil {
				s.manager.counters.rejected.Add(1)
				s.manager.counters.limited.Add(1)
			}
			if !s.queueFrameLocked(frame.Close, id, nil) {
				return started, stopped, cost, items, false
			}
			continue
		}
		live := s.streams[id]
		if live == nil {
			continue
		}
		switch f.Type {
		case frame.Data:
			end, size := uplinkDataRun(frames, i-1)
			allocated, entries := s.appendBackendWriteLocked(live, frames[i-1:end], size)
			i = end
			cost, items = cost-allocated, items-entries
			live.receiveWindow -= uint32(size)
			signal(live.writeNotify)
		case frame.Window:
			increase, _ := frame.WindowAmount(f.Payload)
			live.sendCredit = min(uint64(math.MaxUint32), live.sendCredit+uint64(increase))
			signal(live.creditNotify)
		case frame.Close:
			s.dropStream(id, live)
			stopped = append(stopped, live.backend)
		}
	}
	return started, stopped, cost, items, true
}

func (s *Session) attachStream(id uint32) *backendStream {
	if len(s.streams) >= s.limits.MaxStreamsPerSession || (s.manager != nil && !s.manager.acquireStream(s.quota)) {
		return nil
	}
	conn := newBackendStream(s, id)
	s.streams[id] = &streamState{
		backend: conn, receiveWindow: frame.InitialStreamWindow, sendCredit: frame.InitialStreamWindow,
		creditNotify: make(chan struct{}, 1), writeNotify: make(chan struct{}, 1),
	}
	return conn
}

func (s *Session) dropStream(id uint32, stream *streamState) {
	delete(s.streams, id)
	s.releaseStreamWritesLocked(stream)
	s.rememberClosedLocked(id)
}

func (s *Session) appendBackendWriteLocked(state *streamState, frames []frame.Frame, size int) (int, int) {
	cost := size + queueItemCost
	items := 1
	if last := len(state.writes) - 1; last >= 0 {
		old := state.writes[last]
		length := len(old) + size
		if length <= cap(old) {
			data := old[:length]
			copyUplinkData(data[len(old):], frames)
			state.writes[last] = data
			cost, items = 0, 0
		} else if length <= frame.DataChunk && s.accountBuffer(cap(old)) {
			capacity := min(frame.DataChunk, max(length, min(2*cap(old), cap(old)+cost)))
			data := make([]byte, length, capacity)
			copy(data, old)
			copyUplinkData(data[len(old):], frames)
			state.writes[last] = data
			cost, items = capacity-cap(old), 0
			s.accountBuffer(-cap(old))
		}
	}
	if items != 0 {
		var data []byte
		if len(frames) == 1 {
			payload := frames[0].Payload
			// A full copy of a single payload lets Go skip clearing the slice.
			data = make([]byte, len(payload))
			copy(data, payload)
		} else {
			data = make([]byte, size)
			copyUplinkData(data, frames)
		}
		state.writes = append(state.writes, data)
	}
	state.uncreditedBytes += size
	state.queuedWriteCost += cost
	return cost, items
}

func copyUplinkData(dst []byte, frames []frame.Frame) {
	offset := copy(dst, frames[0].Payload)
	for _, f := range frames[1:] {
		offset += copy(dst[offset:], f.Payload)
	}
}

func (s *Session) nextWrite(backend *backendStream) ([]byte, *streamState) {
	for {
		s.mu.Lock()
		state := s.streams[backend.id]
		if s.closed || state == nil || state.backend != backend {
			s.mu.Unlock()
			return nil, nil
		}
		if len(state.writes) != 0 {
			queued := state.writes
			result := queued[0]
			queued[0] = nil
			if len(queued) > 1 {
				state.writes, state.writesTrimmed = queued[1:], true
			} else if state.writesTrimmed {
				state.writes, state.writesTrimmed = nil, false
			} else {
				// Retain the cleared one-entry allocation for the next write.
				state.writes = queued[:0]
			}
			state.activeWriteCost = cap(result) + queueItemCost
			state.queuedWriteCost -= state.activeWriteCost
			s.mu.Unlock()
			return result, state
		}
		notify := state.writeNotify
		s.mu.Unlock()
		select {
		case <-notify:
		case <-s.lifetime.Done():
			return nil, nil
		case <-backend.ctx.Done():
			return nil, nil
		}
	}
}

func (s *Session) backendDrained(backend *backendStream, amount int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.streams[backend.id]
	if s.closed || state == nil || state.backend != backend || amount <= 0 || amount > state.uncreditedBytes || uint64(state.receiveWindow)+uint64(amount) > frame.InitialStreamWindow {
		return false
	}
	state.uncreditedBytes -= amount
	state.receiveWindow += uint32(amount)
	if !s.queueFrameLocked(frame.Window, backend.id, frame.WindowPayload(uint32(amount))) {
		return false
	}
	return true
}

func (s *Session) backendWriteFinished(state *streamState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cost := state.activeWriteCost
	state.activeWriteCost = 0
	if s.streams[state.backend.id] != state {
		s.detachedCost -= cost
		s.detachedItems--
	}
	s.releasePendingLocked(cost, 1)
}

func (s *Session) reserveBackendRead(backend *backendStream, want int, peerDone <-chan struct{}) int {
	for {
		s.mu.Lock()
		state := s.streams[backend.id]
		if s.closed || state == nil || state.backend != backend {
			s.mu.Unlock()
			return 0
		}
		n := s.dataFrameAllowanceLocked(int(min(uint64(want), state.sendCredit)))
		var global <-chan struct{}
		if n > 0 && s.manager != nil {
			n, global = s.manager.reserveDownlinkRead(n)
		}
		if n > 0 {
			cost := n + dataFrameOverhead
			s.pendingCost += cost
			s.pendingItems++
			// The reader owns this memory until it commits to the queue.
			s.detachedCost += cost
			s.detachedItems++
			s.mu.Unlock()
			return n
		}
		notify := state.creditNotify
		budgetNotify := s.budgetSignalLocked()
		s.mu.Unlock()
		select {
		case <-notify:
		case <-budgetNotify:
		case <-global:
		case <-peerDone:
			return 0
		case <-s.lifetime.Done():
			return 0
		case <-backend.ctx.Done():
			return 0
		}
	}
}

func (s *Session) finishBackendRead(backend *backendStream, encoded []byte, n int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cost := cap(encoded) + queueItemCost
	s.detachedCost -= cost
	s.detachedItems--
	id := backend.id
	state := s.streams[id]
	q := s.downlinkQueueLocked(id)
	if n <= 0 || n > len(encoded)-frame.HeaderSize || state == nil || state.backend != backend ||
		uint64(n) > state.sendCredit || q == nil {
		recycleDownlinkFrame(encoded)
		s.releasePendingLocked(cost, 1)
		return false
	}
	encoded = encoded[:frame.HeaderSize+n]
	if s.coalesceDownlinkLocked(q, id, encoded[frame.HeaderSize:]) {
		recycleDownlinkFrame(encoded)
		s.releasePendingLocked(cost, 1)
	} else {
		frame.WriteHeader(encoded, frame.Data, id)
		q.pendingFrames = append(q.pendingFrames, encoded)
	}
	state.sendCredit -= uint64(n)
	signal(q.notify)
	return true
}

func (s *Session) backendClosed(backend *backendStream) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if live := s.streams[backend.id]; live != nil && live.backend == backend {
		s.dropStream(backend.id, live)
		if !s.queueFrameLocked(frame.Close, backend.id, nil) {
			s.closeLocked()
		}
	}
}

func (s *Session) downlinkQueueLocked(id uint32) *downQueue {
	if !s.usesCarrierLanes() {
		return &s.downQueue
	}
	if lane := s.carrierLanes[id]; lane != nil {
		return &lane.downQueue
	}
	return nil
}

func (s *Session) queueFrameLocked(kind frame.Type, id uint32, payload []byte) bool {
	q := s.downlinkQueueLocked(id)
	if q == nil {
		return false
	}
	if kind == frame.Window {
		if position, ok := q.pendingWindows[id]; ok {
			encoded := q.pendingFrames[position-q.pendingBase][frame.HeaderSize:]
			updated := uint64(binary.BigEndian.Uint32(encoded)) + uint64(binary.BigEndian.Uint32(payload))
			if updated <= math.MaxUint32 {
				binary.BigEndian.PutUint32(encoded, uint32(updated))
				signal(q.notify)
				return true
			}
		}
	}
	class := pendingControl
	if kind == frame.Data {
		class = pendingDownlink
		if s.coalesceDownlinkLocked(q, id, payload) {
			signal(q.notify)
			return true
		}
	}
	cost := frame.HeaderSize + len(payload) + queueItemCost
	if !s.reservePendingLocked(cost, 1, class) {
		return false
	}
	if kind == frame.Window {
		q.pendingWindows[id] = q.pendingBase + uint64(len(q.pendingFrames))
	}
	q.pendingFrames = append(q.pendingFrames, frame.Encode(kind, id, payload))
	signal(q.notify)
	return true
}

func (s *Session) coalesceDownlinkLocked(q *downQueue, id uint32, payload []byte) bool {
	if len(q.pendingFrames) == 0 {
		return false
	}
	last := &q.pendingFrames[len(q.pendingFrames)-1]
	word := binary.BigEndian.Uint32(*last)
	return word == uint32(frame.Data)<<24|id && s.mergeDownlinkLocked(last, payload)
}

func (s *Session) mergeDownlinkLocked(entry *[]byte, data []byte) bool {
	old := *entry
	need := len(old) + len(data)
	limit := min(frame.HeaderSize+min(frame.DataChunk, s.limits.MaxFramePayload), s.limits.CarrierBatchBytes)
	if need > limit {
		return false
	}
	if need > cap(old) {
		capacity := min(limit, max(need, cap(old)+cap(old)/4))
		extra := capacity - cap(old)
		if !s.reservePendingLocked(extra, 0, pendingDownlink) {
			return false
		}
		if !s.accountBuffer(cap(old)) {
			s.releasePendingLocked(extra, 0)
			return false
		}
		*entry = make([]byte, len(old), capacity)
		copy(*entry, old)
		s.accountBuffer(-cap(old))
	}
	*entry = append(*entry, data...)
	binary.BigEndian.PutUint32((*entry)[4:8], uint32(need-frame.HeaderSize))
	return true
}

func (s *Session) packDownlink(q *downQueue) downBatch {
	count, bytes, cost := 0, 0, 0
	for _, encoded := range q.pendingFrames {
		if count == frame.MaxBatchFrames || (count > 0 && len(encoded) > s.limits.CarrierBatchBytes-bytes) {
			break
		}
		count++
		bytes += len(encoded)
		cost += cap(encoded) + queueItemCost
	}
	frames, remaining := q.pendingFrames[:count], q.pendingFrames[count:]
	if len(remaining) == 0 {
		clear(q.pendingWindows)
		q.pendingBase = 0
	} else if len(q.pendingWindows) != 0 {
		q.retirePendingWindows(frames)
	}
	batch := downBatch{size: bytes, cost: cost, items: count}
	if count == 1 {
		batch.body.Bytes = frames[0]
	} else {
		if s.carrier == config.CarrierWebSocket || s.carrier == config.CarrierWebSocketLanes {
			// Charge both representations until the source entries are cleared.
			// The existing queue charge covers the retained storage afterwards.
			batch.body = frame.BorrowBatchBuffer(bytes, min(s.limits.CarrierBatchBytes, cost), s.accountBuffer)
		}
		if body := batch.body.Bytes; body != nil {
			defer s.accountBuffer(-cap(body))
			for _, encoded := range frames {
				body = body[copy(body, encoded):]
				recycleDownlinkFrame(encoded)
			}
		} else if len(remaining) == 0 && !q.trimmedFrames {
			// Move the complete frame list to the writer. A sliced list could
			// keep storage from earlier batches alive through a slow response.
			batch.parts = frames
			frames = nil
		} else {
			// Keep the writer independent of frames still waiting in the queue.
			batch.parts = append([][]byte(nil), frames...)
		}
	}
	clear(frames)
	q.pendingFrames = remaining
	q.trimmedFrames = len(remaining) != 0
	if len(q.pendingFrames) == 0 {
		q.pendingFrames = nil
	}
	return batch
}

func (q *downQueue) retirePendingWindows(packed [][]byte) {
	count := uint64(len(packed))
	if len(q.pendingWindows) <= len(packed) {
		for id, position := range q.pendingWindows {
			if position-q.pendingBase < count {
				delete(q.pendingWindows, id)
			}
		}
	} else {
		for i, encoded := range packed {
			if encoded[0] != byte(frame.Window) {
				continue
			}
			id := binary.BigEndian.Uint32(encoded) & frame.MaxStreamID
			// A later WINDOW for the same stream may still be waiting.
			if position, ok := q.pendingWindows[id]; ok && position-q.pendingBase == uint64(i) {
				delete(q.pendingWindows, id)
			}
		}
	}
	if len(q.pendingWindows) == 0 {
		q.pendingBase = 0
	} else {
		q.pendingBase += count
	}
}

func (s *Session) rememberClosedLocked(id uint32) {
	if _, duplicate := s.closedStreams[id]; duplicate {
		return
	}
	if len(s.closedOrder) == s.limits.MaxClosedStreamIDs && len(s.closedOrder) > 0 {
		position := s.closedStart
		retired := s.closedOrder[position]
		s.closedOrder[position] = id
		s.closedStart++
		if s.closedStart == len(s.closedOrder) {
			s.closedStart = 0
		}
		delete(s.closedStreams, retired)
		if lane := s.carrierLanes[retired]; lane != nil {
			delete(s.carrierLanes, retired)
			s.releaseLaneLocked(lane)
		}
	} else {
		s.closedOrder = append(s.closedOrder, id)
	}
	s.closedStreams[id] = struct{}{}
	if lane := s.carrierLanes[id]; lane != nil {
		signal(lane.notify)
	}
}

func (s *Session) releaseLaneLocked(lane *carrierLane) {
	s.discardDownlinkLocked(&lane.downQueue)
	signal(lane.notify)
}

func (s *Session) discardDownlinkLocked(queue *downQueue) {
	s.retireDownLocked(&queue.unacked)
	var total int
	for _, encoded := range queue.pendingFrames {
		total += cap(encoded) + queueItemCost
		recycleDownlinkFrame(encoded)
	}
	s.releasePendingLocked(total, len(queue.pendingFrames))
	queue.pendingFrames, queue.pendingWindows = nil, nil
	queue.pendingBase = 0
	queue.trimmedFrames = false
}

func (s *Session) releaseStreamWritesLocked(state *streamState) {
	if active := state.activeWriteCost; active != 0 {
		s.detachedCost += active
		s.detachedItems++
	}
	s.releasePendingLocked(state.queuedWriteCost, len(state.writes))
	state.writes, state.queuedWriteCost, state.uncreditedBytes = nil, 0, 0
	state.writesTrimmed = false
}

func (s *Session) closeLocked() {
	if s.closed {
		return
	}
	s.closed = true
	s.cancel()
	s.discardDownlinkLocked(&s.downQueue)
	for _, lane := range s.carrierLanes {
		s.releaseLaneLocked(lane)
	}
	for _, value := range s.streams {
		s.releaseStreamWritesLocked(value)
		value.backend.close()
	}
	s.carrierLanes, s.websocketLanes = nil, nil
	s.closedStreams, s.closedOrder = nil, nil
	s.streams = nil
	s.usedStreamIDs.extra = nil
	s.releasePendingLocked(s.pendingCost-s.detachedCost, s.pendingItems-s.detachedItems)
	if s.manager != nil {
		go s.manager.sessionFinished(s)
	}
}

func signal(channel chan struct{}) {
	select {
	case channel <- struct{}{}:
	default:
	}
}
