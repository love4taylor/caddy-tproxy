package tproxy

import (
	"errors"
	"sync"
	"sync/atomic"
)

const (
	maxBackendBufferBytes = 64 << 20
	maxPooledBufferSize   = 128 << 10
)

var errBufferBudget = errors.New("tproxy buffer capacity exhausted")

// The backend's sublimit leaves room for the relay's windows and control frames.
type bufferBudget struct {
	used   atomic.Int64
	denied atomic.Uint64
	shared func(int) bool
}

func (b *bufferBudget) reserve(size int) bool {
	if b == nil {
		return true
	}
	n := int64(size)
	for {
		used := b.used.Load()
		if n > maxBackendBufferBytes-used {
			b.denied.Add(1)
			return false
		}
		if b.used.CompareAndSwap(used, used+n) {
			break
		}
	}
	if b.shared == nil || b.shared(size) {
		return true
	}
	b.used.Add(-n)
	b.denied.Add(1)
	return false
}

func (b *bufferBudget) release(size int) {
	if b != nil {
		if b.shared != nil {
			b.shared(-size)
		}
		b.used.Add(-int64(size))
	}
}

// Ownership moves from the reader to the queue and then to the writer.
type ownedBuffer struct {
	data   []byte
	pooled *pooledPacket
	budget *bufferBudget
}

var (
	packet256    = packetPool(256)
	packet4K     = packetPool(4 << 10)
	packet16K    = packetPool(16 << 10)
	packet72K    = packetPool(72 << 10)
	largePackets largePacketCache
)

func borrowBuffer(size int, budget *bufferBudget) (ownedBuffer, error) {
	pool, capacity := bufferClass(size)
	if !budget.reserve(capacity) {
		return ownedBuffer{}, errBufferBudget
	}
	if budget == nil {
		// A nil budget is used for short-lived handshake and fixture frames.
		return ownedBuffer{data: make([]byte, size, capacity)}, nil
	}
	if pool == nil {
		data := largePackets.take(size)
		if data == nil {
			data = make([]byte, size)
		}
		return ownedBuffer{data: data, budget: budget}, nil
	}
	packet := pool.Get().(*pooledPacket)
	return ownedBuffer{data: packet.buffer[:size], pooled: packet, budget: budget}, nil
}

func bufferClass(size int) (*sync.Pool, int) {
	switch {
	case size <= 256:
		return packet256, 256
	case size <= 4<<10:
		return packet4K, 4 << 10
	case size <= 16<<10:
		return packet16K, 16 << 10
	case size <= 32<<10:
		return packet32K, 32 << 10
	case size <= 64<<10:
		return packet64K, 64 << 10
	case size <= 72<<10:
		return packet72K, 72 << 10
	case size <= maxPooledBufferSize:
		return packet128K, maxPooledBufferSize
	default:
		return nil, size
	}
}

func (p ownedBuffer) release() {
	capacity := cap(p.data)
	if p.budget != nil && capacity > maxPooledBufferSize && capacity <= maxRPCPacket {
		// Erase the entire allocation before it becomes idle storage.
		data := p.data[:capacity]
		clear(data)
		p.discard()
		largePackets.put(data)
		return
	}
	p.discard()
}

// A failed read can discard a large allocation without touching unread pages.
func (p ownedBuffer) discard() {
	p.budget.release(cap(p.data))
	if p.pooled != nil {
		p.pooled.release()
	}
}

// Large buffers use exact capacities to preserve admission under both byte
// limits. Keep only the two most recently released buffers across backends.
type largePacketCache struct {
	mu   sync.Mutex
	idle [2][]byte
}

func (c *largePacketCache) take(size int) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, data := range c.idle {
		if len(data) == size {
			copy(c.idle[i:], c.idle[i+1:])
			c.idle[len(c.idle)-1] = nil
			return data
		}
	}
	return nil
}

func (c *largePacketCache) put(data []byte) {
	c.mu.Lock()
	c.idle[1] = c.idle[0]
	c.idle[0] = data
	c.mu.Unlock()
}
