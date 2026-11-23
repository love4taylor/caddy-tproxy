package session

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/love4taylor/caddy-tproxy/internal/frame"
)

type backendStream struct {
	session *Session
	id      uint32
	ctx     context.Context
	cancel  context.CancelFunc
}

func newBackendStream(owner *Session, id uint32) *backendStream {
	ctx, cancel := context.WithCancel(context.Background())
	return &backendStream{session: owner, id: id, ctx: ctx, cancel: cancel}
}

func (b *backendStream) close() { b.cancel() }

func (b *backendStream) run() {
	owner := b.session
	defer owner.backendWG.Done()
	if owner.manager != nil {
		defer owner.manager.streamFinished(owner.quota)
	}
	defer owner.backendClosed(b)
	defer b.close()

	// The embedded dial reports readiness after processing the initial bytes.
	var reported sync.Once
	ready := func(err error) {
		if owner.manager != nil {
			reported.Do(func() { owner.manager.backendDialFinished(owner.quota, err != nil && b.ctx.Err() == nil) })
		}
	}
	defer func() { ready(nil) }()

	dial := owner.profile.DialBackend
	if dial == nil {
		ready(ErrClosed)
		return
	}
	conn, err := dial(b.ctx, ready)
	if err != nil {
		ready(err)
		return
	}
	if conn == nil {
		ready(ErrClosed)
		return
	}
	defer conn.Close()
	interrupt := context.AfterFunc(b.ctx, func() { _ = conn.Close() })
	defer interrupt()

	var writer sync.WaitGroup
	writer.Go(func() {
		b.send(conn)
		_ = conn.Close()
	})
	b.receive(conn)
	b.close()
	// Closing synchronously is required before waiting for an idle writer.
	_ = conn.Close()
	writer.Wait()
}

func (b *backendStream) send(out io.Writer) {
	for {
		data, state := b.session.nextWrite(b)
		if state == nil {
			return
		}
		ok := b.write(out, data)
		b.session.backendWriteFinished(state)
		if !ok {
			return
		}
	}
}

func (b *backendStream) write(out io.Writer, data []byte) bool {
	for len(data) > 0 {
		n, err := out.Write(data)
		if n < 0 || n > len(data) {
			return false
		}
		if n != 0 && !b.session.backendDrained(b, n) {
			return false
		}
		if err != nil || n == 0 {
			return false
		}
		data = data[n:]
	}
	return true
}

type bufferedStreamReader interface {
	ReadWithBuffer(int, func(int) ([]byte, error)) (int, error)
	ReadDone() <-chan struct{}
}

const backendReadBufferSize = frame.HeaderSize + frame.DataChunk

// Bound idle storage across all sessions. Live buffers are charged before use.
var backendReadBuffers = make(chan []byte, 24)

func borrowBackendReadBuffer(size int) []byte {
	if size == backendReadBufferSize {
		select {
		case storage := <-backendReadBuffers:
			return storage
		default:
		}
	}
	return make([]byte, size)
}

func recycleDownlinkFrame(storage []byte) {
	if cap(storage) == backendReadBufferSize {
		select {
		case backendReadBuffers <- storage[:backendReadBufferSize]:
		default:
		}
	}
}

func (b *backendStream) receive(conn net.Conn) {
	s := b.session
	reader, direct := conn.(bufferedStreamReader)
	var peerDone <-chan struct{}
	if direct {
		peerDone = reader.ReadDone()
	}
	limit := min(frame.DataChunk, s.limits.MaxFramePayload)
	var buffer []byte
	allocate := func(want int) ([]byte, error) {
		if buffer != nil || want <= 0 || want > limit {
			return nil, ErrProtocol
		}
		n := s.reserveBackendRead(b, want, peerDone)
		if n == 0 {
			return nil, ErrClosed
		}
		buffer = borrowBackendReadBuffer(frame.HeaderSize + n)
		return buffer[frame.HeaderSize:], nil
	}
	for {
		var n int
		var err error
		if direct {
			n, err = reader.ReadWithBuffer(limit, allocate)
		} else {
			var dst []byte
			dst, err = allocate(limit)
			if err == nil {
				n, err = conn.Read(dst)
			}
		}
		delivered := buffer != nil && s.finishBackendRead(b, buffer, n)
		buffer = nil
		if err != nil || !delivered {
			return
		}
	}
}
