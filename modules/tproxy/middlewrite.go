package tproxy

import "net"

const (
	middleWriteQueue        = 128
	middleControlSlots      = 16
	middleBatchFrames       = 16
	middleBatchBytes        = 128 << 10
	middleProxyRequestBytes = 56
	middleRequestHeadroom   = rpcFrameHeader + middleProxyRequestBytes
	middleInPlacePayload    = 64 << 10
)

type middleWrite struct {
	prefix  []byte
	body    []byte
	wire    []byte // Optional backing storage with headroom before body.
	result  chan error
	stream  *middleStream
	stop    <-chan struct{}
	control [12]byte
}

func (r *middleWrite) canceled() bool {
	if r.stream != nil && r.stream.detached.Load() {
		return true
	}
	select {
	case <-r.stop:
		return true
	default:
		return false
	}
}

func (m *middleConn) queueWrite(request *middleWrite) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	for {
		if err := m.queueWriteLocked(request); err != errBufferBudget {
			m.signalWriteSpaceLocked()
			return err
		}
		if m.writeSpace == nil {
			m.writeSpace = make(chan struct{}, 1)
		}
		m.writeWaiters.Add(1)
		// The writer dequeues without writeMu. Recheck after registering so
		// a dequeue that saw no waiters cannot leave this sender asleep.
		if len(m.writes) >= m.dataWriteLimit() {
			space := m.writeSpace
			m.writeMu.Unlock()
			select {
			case <-space:
			case <-request.stop:
			case <-m.done:
			}
			m.writeMu.Lock()
		}
		m.writeWaiters.Add(-1)
	}
}

func (m *middleConn) dataWriteLimit() int { return cap(m.writes) - middleControlSlots }

func (m *middleConn) signalWriteSpaceLocked() {
	if m.writeSpace != nil && m.writeWaiters.Load() > 0 && len(m.writes) < m.dataWriteLimit() {
		// Wake one sender. On admission or cancellation it wakes the next
		// sender if space remains, avoiding a burst of lock contention.
		select {
		case m.writeSpace <- struct{}{}:
		default:
		}
	}
}

func (m *middleConn) queueWriteLocked(request *middleWrite) error {
	if request.canceled() {
		return net.ErrClosed
	}
	select {
	case <-m.done:
		return net.ErrClosed
	default:
	}
	if (request.result != nil || le.Uint32(request.control[:]) == rpcPing) && len(m.writes) >= m.dataWriteLimit() {
		return errBufferBudget
	}
	select {
	case m.writes <- request:
		return nil
	default:
		return errBufferBudget
	}
}

func (m *middleConn) sendControl(op uint32, value uint64) error {
	m.writeMu.Lock()
	if op == rpcCloseConn {
		// Late answers for the same stream share the pending close frame.
		if _, exists := m.pendingCloses[value]; exists {
			m.writeMu.Unlock()
			return nil
		}
	}
	request := new(middleWrite)
	le.PutUint32(request.control[:], op)
	le.PutUint64(request.control[4:], value)
	request.prefix = request.control[:]
	err := m.queueWriteLocked(request)
	if err == nil && op == rpcCloseConn {
		if m.pendingCloses == nil {
			m.pendingCloses = make(map[uint64]struct{})
		}
		m.pendingCloses[value] = struct{}{}
	}
	m.writeMu.Unlock()
	if err == errBufferBudget && op != rpcPing {
		// Without the control frame, upstream can retain a closed stream or
		// wait for a reply that cannot arrive. Close the shared socket instead.
		m.stats.controlOverflows.Add(1)
		m.close()
	}
	return err
}

func (m *middleConn) writeStreams() {
	var next *middleWrite
	for {
		first := next
		if first == nil {
			var ok bool
			first, ok = <-m.writes
			if !ok {
				return
			}
		}
		next = nil
		var requests [middleBatchFrames]*middleWrite
		requests[0] = first
		count, size := 1, rpcFrameSize(first.prefix, first.body)
	drain:
		for count < len(requests) && size < middleBatchBytes {
			select {
			case request, ok := <-m.writes:
				if !ok {
					break drain
				}
				frameSize := rpcFrameSize(request.prefix, request.body)
				if size+frameSize > middleBatchBytes {
					next = request
					break drain
				}
				requests[count] = request
				count++
				size += frameSize
			default:
				break drain
			}
		}
		if m.writeWaiters.Load() > 0 {
			m.writeMu.Lock()
			m.signalWriteSpaceLocked()
			m.writeMu.Unlock()
		}
		m.writeQueued(requests[:count], size)
	}
}

func (m *middleConn) writeQueued(requests []*middleWrite, size int) {
	live := requests[:0]
	for _, request := range requests {
		if request.canceled() {
			size -= rpcFrameSize(request.prefix, request.body)
			request.result <- net.ErrClosed
		} else {
			live = append(live, request)
		}
	}
	if len(live) == 0 {
		return
	}
	err := net.ErrClosed
	select {
	case <-m.done:
	default:
		err = m.writeBatch(live, size)
		if err == errBufferBudget {
			if len(live) > 1 {
				// Nothing was encoded. Retry in order, checking each stream again.
				for i, request := range live {
					m.writeQueued(live[i:i+1], rpcFrameSize(request.prefix, request.body))
				}
				return
			}
			m.stats.writeRejected.Add(1)
		} else if err != nil {
			m.streamMu.Lock()
			if !m.closed {
				m.writeErr = err
				m.stats.writeFailures.Add(1)
				m.closeLocked()
			}
			m.streamMu.Unlock()
		}
	}
	for _, request := range live {
		if request.result != nil {
			request.result <- err
		} else if le.Uint32(request.control[:]) == rpcCloseConn {
			m.writeMu.Lock()
			delete(m.pendingCloses, le.Uint64(request.control[4:]))
			m.writeMu.Unlock()
		}
	}
}

func (m *middleConn) writeBatch(requests []*middleWrite, size int) error {
	frames := len(requests)
	stored := rpcPaddedSize(size)
	var wire []byte
	if requests[0].wire != nil && stored <= cap(requests[0].wire) {
		request := requests[0]
		wire = m.appendFrameHeader(request.wire, rpcFrameSize(request.prefix, request.body))
		wire = append(wire, request.prefix...)
		// The payload is already at its wire offset in the same buffer.
		wire = m.finishFrame(wire[:len(wire)+len(request.body)], 0)
		requests = requests[1:]
	} else if stored <= len(m.writeScratch) {
		// Keep small control messages available at the payload budget limit.
		wire = m.writeScratch[:0]
	} else {
		buffer, err := borrowBuffer(stored, m.budget)
		if err != nil {
			return err
		}
		defer buffer.release()
		wire = buffer.data[:0]
	}
	for _, request := range requests {
		wire = m.appendFrame(wire, rpcFrameSize(request.prefix, request.body), request.prefix, request.body)
	}
	err := m.flushFrames(wire)
	if err == nil {
		m.stats.writeBatches.Add(1)
		m.stats.writeFrames.Add(uint64(frames))
	}
	return err
}
