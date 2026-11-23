package tproxy

import (
	"crypto/sha256"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
)

const (
	handshakeReplayTTL      = 2 * time.Minute
	handshakeReplayCapacity = 16_384
)

// Overlapping Caddy configurations share the window for each key on reload.
var handshakeWindows = caddy.NewUsagePool()

type handshakeReplays struct {
	mu      sync.Mutex
	entries map[[sha256.Size]byte]struct{}
	queue   []handshakeReplay
	head    int
}

type handshakeReplay struct {
	id      [sha256.Size]byte
	expires time.Time
}

func (r *handshakeReplays) remember(id [sha256.Size]byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.admit(id, time.Now())
}

// admit runs with mu held so timestamps and insertion order agree.
func (r *handshakeReplays) admit(id [sha256.Size]byte, now time.Time) bool {
	for len(r.entries) > 0 && !now.Before(r.queue[r.head].expires) {
		delete(r.entries, r.queue[r.head].id)
		r.head++
		if r.head == len(r.queue) {
			r.head = 0
		}
	}
	count := len(r.entries)
	if _, found := r.entries[id]; found || count >= handshakeReplayCapacity {
		return false
	}
	if r.entries == nil {
		r.entries = make(map[[sha256.Size]byte]struct{})
	}
	if count == len(r.queue) {
		queue := make([]handshakeReplay, min(handshakeReplayCapacity, max(64, 2*count)))
		n := copy(queue, r.queue[r.head:])
		copy(queue[n:], r.queue[:r.head])
		r.queue, r.head = queue, 0
	}
	tail := r.head + count
	if tail >= len(r.queue) {
		tail -= len(r.queue)
	}
	r.queue[tail] = handshakeReplay{id: id, expires: now.Add(handshakeReplayTTL)}
	r.entries[id] = struct{}{}
	return true
}
