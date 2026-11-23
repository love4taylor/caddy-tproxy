package server

import (
	"net/http"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/love4taylor/caddy-tproxy/internal/session"
)

type downlinkWrite struct {
	http.ResponseWriter
	controller http.ResponseController
	idle       *caddyhttp.IdleTimeoutWriter
	transport  *http.ResponseController
	idleGate   http.ResponseController
	mu         sync.Mutex
	expired    bool

	stop     func() bool
	callback sync.WaitGroup
	finished chan struct{}
}

func interruptDownlinkOnClose(r *http.Request, controller *http.ResponseController, active *session.Session) *downlinkWrite {
	d := &downlinkWrite{controller: *controller}
	_, d.idle = caddyhttp.IdleTimeoutsFromContext(r.Context())
	if d.idle != nil {
		// IdleTimeoutWriter keeps request-local state, and an idle reset can
		// replace an expired transport deadline. Gate its transport calls
		// for the duration of the response, including its final flush.
		d.ResponseWriter = d.idle.ResponseWriter
		d.transport = d.idle.Ctrl
		d.idleGate = *http.NewResponseController(d)
		d.idle.Ctrl = &d.idleGate
	}
	if r.ProtoMajor == 1 && r.TLS != nil {
		d.finished = make(chan struct{})
	}
	d.callback.Add(1)
	d.stop = active.OnClose(d.interrupt)
	return d
}

func (d *downlinkWrite) interrupt() {
	defer d.callback.Done()
	if d.expire() != nil || d.finished == nil {
		return
	}
	// After a timed-out HTTP/1 write, crypto/tls may replace the
	// deadline to send close_notify before returning from Write.
	retry := time.NewTicker(10 * time.Millisecond)
	defer retry.Stop()
	for {
		select {
		case <-d.finished:
			return
		case <-retry.C:
			if d.expire() != nil {
				return
			}
		}
	}
}

func (d *downlinkWrite) finish() {
	if d.finished != nil {
		close(d.finished)
	}
	if !d.stop() {
		// A response controller must not outlive this handler.
		d.callback.Wait()
		if d.idle != nil {
			// Preserve the expired ceiling through Caddy's handler cleanup.
			_ = d.idle.SetWriteDeadline(time.Now())
		}
	}
	if d.idle != nil {
		d.idle.Ctrl = d.transport
	}
}

func (d *downlinkWrite) SetWriteDeadline(deadline time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.expired {
		return nil
	}
	return d.transport.SetWriteDeadline(deadline)
}

func (d *downlinkWrite) expire() error {
	if d.idle == nil {
		return d.controller.SetWriteDeadline(time.Now())
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.expired = true
	return d.transport.SetWriteDeadline(time.Now())
}
