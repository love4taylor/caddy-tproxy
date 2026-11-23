package tproxy

import (
	"io"
	"net"
	"sync"
)

type pipeOutput struct {
	ready chan int
	done  chan struct{}
	once  sync.Once
}

func (p *pipeOutput) close() {
	p.once.Do(func() { close(p.done) })
}

type relayPipe struct {
	net.Conn
	output    *pipeOutput
	remaining int
}

func (p *relayPipe) ReadDone() <-chan struct{} { return p.output.done }

// ReadWithBuffer waits for an actual write before requesting a buffer, so an
// idle logical stream does not pin a media-sized allocation. Only the relay's
// single reader uses this method.
func (p *relayPipe) ReadWithBuffer(limit int, allocate func(int) ([]byte, error)) (int, error) {
	if p.remaining == 0 {
		select {
		case p.remaining = <-p.output.ready:
		case <-p.output.done:
			return 0, io.EOF
		}
	}
	buffer, err := allocate(min(limit, p.remaining))
	if err != nil {
		return 0, err
	}
	n, err := p.Conn.Read(buffer)
	p.remaining -= n
	return n, err
}

func (p *relayPipe) Close() error {
	p.output.close()
	return p.Conn.Close()
}

type proxyPipe struct {
	net.Conn
	output *pipeOutput
}

func (p *proxyPipe) Write(data []byte) (int, error) {
	if len(data) > 0 {
		select {
		case p.output.ready <- len(data):
		default:
			// The ordinary net.Conn Read path does not consume these notices.
		}
	}
	return p.Conn.Write(data)
}

func (p *proxyPipe) Close() error {
	p.output.close()
	return p.Conn.Close()
}

func newProxyPipe() (*relayPipe, *proxyPipe) {
	relay, proxy := net.Pipe()
	output := &pipeOutput{ready: make(chan int, 1), done: make(chan struct{})}
	return &relayPipe{Conn: relay, output: output}, &proxyPipe{Conn: proxy, output: output}
}
