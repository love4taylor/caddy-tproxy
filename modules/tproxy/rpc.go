package tproxy

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	rpcNonce     = 0x7acb87aa
	rpcHandshake = 0x7682eef5
	rpcProxyReq  = 0x36cef1ee
	rpcProxyAns  = 0x4403da0d
	rpcCloseExt  = 0x5eb634a2
	rpcCloseConn = 0x1fcf425d
	rpcSimpleAck = 0x3bac409b
	rpcPing      = 0x5730a2df
	rpcPong      = 0x8430eaa7

	rpcFrameHeader       = 8
	rpcFrameOverhead     = rpcFrameHeader + 4
	rpcHandshakeBody     = 32
	rpcHandshakePacket   = rpcHandshakeBody + rpcFrameOverhead
	rpcControlBody       = 12
	rpcSimpleAckBody     = 16
	rpcProxyAnswerHeader = 16
	maxRPCPacket         = maxTransportPacket + 1024
)

var (
	le          = binary.LittleEndian
	errRPCFrame = errors.New("invalid Telegram RPC frame sequence or checksum")
)

type rpcFramePrefix struct {
	body []byte
	size int // Full body length, even when only a prefix was retained.
}

type middleConn struct {
	conn          net.Conn
	reader        io.Reader
	readSource    middleReadSource
	readSeq       int32
	writeSeq      int32
	encrypt       cipher.BlockMode
	writeMu       sync.Mutex
	writes        chan *middleWrite
	writeSpace    chan struct{} // Allocated on demand under writeMu.
	writeWaiters  atomic.Int32
	pendingCloses map[uint64]struct{} // Queued or in-flight RPC_CLOSE_CONN, guarded by writeMu.
	writeErr      error               // Written by the writer, read after it exits.
	wire          packetBuffer
	writeScratch  [middleBatchFrames * 32]byte
	readHeader    [4]byte
	smallFrame    [rpcFrameOverhead + rpcSimpleAckBody]byte
	discardHead   [4 + rpcProxyAnswerHeader]byte // Sequence number and answer header.
	discardTail   [4]byte
	discardBuffer []byte
	ourIP         netip.Addr

	streamMu  sync.Mutex
	streams   map[uint64]*middleStream
	done      chan struct{}
	closed    bool
	idleSince time.Time
	warm      bool
	retired   bool
	budget    *bufferBudget
	stats     *backendStats
}

// For a frame already buffered by bufio or CBC, there is no socket read to
// time out. A frame that reaches the socket keeps one deadline across reads.
type middleReadSource struct {
	conn        net.Conn
	armDeadline bool
}

func (s *middleReadSource) Read(dst []byte) (int, error) {
	if s.armDeadline {
		s.armDeadline = false
		_ = s.conn.SetReadDeadline(time.Now().Add(middleReadTimeout))
	}
	return s.conn.Read(dst)
}

func negotiateMiddle(conn net.Conn, secret [128]byte, publicIP netip.Addr) (*middleConn, error) {
	source, sourceOK := conn.LocalAddr().(*net.TCPAddr)
	destination, destinationOK := conn.RemoteAddr().(*net.TCPAddr)
	if !sourceOK || !destinationOK {
		return nil, errors.New("Telegram middle-end requires a TCP connection")
	}
	local, remote := source.AddrPort(), destination.AddrPort()
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	if publicIP.IsValid() {
		local = netip.AddrPortFrom(publicIP, local.Port())
	}
	if !local.Addr().Is4() || !remote.Addr().Is4() {
		return nil, errors.New("Telegram middle-end requires IPv4")
	}
	m := &middleConn{conn: conn, readSeq: -2, writeSeq: -2, ourIP: local.Addr()}
	m.readSource.conn = conn
	wire := bufio.NewReaderSize(&m.readSource, 32<<10)
	m.reader = wire
	var hello [rpcHandshakeBody]byte
	le.PutUint32(hello[:4], rpcNonce)
	copy(hello[4:8], secret[:4])
	le.PutUint32(hello[8:12], 1)
	now := uint32(time.Now().Unix())
	le.PutUint32(hello[12:16], now)
	rand.Read(hello[16:])
	if err := m.write(hello[:]); err != nil {
		return nil, fmt.Errorf("send Telegram RPC nonce: %w", err)
	}
	response, err := m.read(rpcHandshakePacket)
	if err != nil {
		return nil, fmt.Errorf("read Telegram RPC nonce: %w", err)
	}
	if len(response) != len(hello) || [12]byte(response) != [12]byte(hello[:]) {
		return nil, errors.New("unexpected Telegram RPC nonce response")
	}
	delta := int32(le.Uint32(response[12:]) - now)
	if delta < -30 || delta > 30 {
		return nil, errors.New("Telegram RPC timestamp differs by more than 30 seconds")
	}

	keys := middleSessionKeys([16]byte(response[16:]), [16]byte(hello[16:]), now, local, remote, &secret)
	tx, rx := &keys[clientDirection], &keys[serverDirection]
	encrypt, _ := aes.NewCipher(tx.key[:])
	m.encrypt = cipher.NewCBCEncrypter(encrypt, tx.iv[:])
	m.reader = &cbcReader{source: wire, decrypt: newRPCDecrypter(rx.key, rx.iv)}
	clear(keys[:])

	var handshake [rpcHandshakeBody]byte
	le.PutUint32(handshake[:4], rpcHandshake)
	process := handshake[8:20]
	le.PutUint32(process[:4], rpcIPv4(local.Addr()))
	le.PutUint16(process[6:8], uint16(os.Getpid()))
	le.PutUint32(process[8:], now)
	// Connections can land on a process with a different advertised address.
	// A zero peer PID asks Telegram to identify itself in the response.
	if err := m.write(handshake[:]); err != nil {
		return nil, fmt.Errorf("send Telegram RPC handshake: %w", err)
	}
	reply, err := m.read(rpcHandshakePacket)
	if err != nil {
		return nil, fmt.Errorf("read Telegram RPC handshake: %w", err)
	}
	if len(reply) != rpcHandshakeBody || le.Uint32(reply) != rpcHandshake || le.Uint32(reply[4:]) != 0 ||
		!bytes.Equal(reply[20:], process) {
		return nil, errors.New("Telegram RPC handshake rejected")
	}
	return m, nil
}

func rpcIPv4(addr netip.Addr) uint32 {
	raw := addr.As4()
	return binary.BigEndian.Uint32(raw[:])
}

func rpcFrameSize(parts ...[]byte) int {
	size := rpcFrameOverhead
	for _, part := range parts {
		size += len(part)
	}
	return size
}

func (m *middleConn) appendFrame(wire []byte, size int, parts ...[]byte) []byte {
	start := len(wire)
	wire = m.appendFrameHeader(wire, size)
	for _, part := range parts {
		wire = append(wire, part...)
	}
	return m.finishFrame(wire, start)
}

func (m *middleConn) appendFrameHeader(wire []byte, size int) []byte {
	wire = le.AppendUint32(wire, uint32(size))
	return le.AppendUint32(wire, uint32(m.writeSeq))
}

func (m *middleConn) finishFrame(wire []byte, start int) []byte {
	wire = le.AppendUint32(wire, crc32.ChecksumIEEE(wire[start:]))
	m.writeSeq++
	return wire
}

func rpcPaddedSize(size int) int {
	return (size + aes.BlockSize - 1) &^ (aes.BlockSize - 1)
}

func (m *middleConn) flushFrames(wire []byte) error {
	if m.encrypt != nil {
		for len(wire)%aes.BlockSize != 0 {
			wire = le.AppendUint32(wire, 4)
		}
		m.encrypt.CryptBlocks(wire, wire)
	}
	_ = m.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return writeFull(m.conn, wire)
}

// Only the handshake and test peer write synchronously to the socket.
func (m *middleConn) write(parts ...[]byte) error {
	size := rpcFrameSize(parts...)
	wire, pooled := m.wire.acquire(rpcPaddedSize(size))
	if pooled != nil {
		defer pooled.release()
	}
	return m.flushFrames(m.appendFrame(wire[:0], size, parts...))
}

func (m *middleConn) read(sizeLimit uint32) ([]byte, error) {
	frame, _, err := m.readFrame(nil, sizeLimit)
	if err != nil {
		return nil, err
	}
	return frame.data[8 : len(frame.data)-4], nil
}

// Short stream frames use connection-local storage. Large frames without a
// destination and frames over budget are validated using bounded scratch space.
func (m *middleConn) readFrame(budget *bufferBudget, sizeLimit uint32) (ownedBuffer, rpcFramePrefix, error) {
	var size uint32
	for padding := 0; padding < 4; padding++ {
		if _, err := io.ReadFull(m.reader, m.readHeader[:]); err != nil {
			return ownedBuffer{}, rpcFramePrefix{}, err
		}
		size = le.Uint32(m.readHeader[:])
		if size != 4 {
			break
		}
	}
	if size < 16 || size > sizeLimit || size%4 != 0 {
		return ownedBuffer{}, rpcFramePrefix{}, fmt.Errorf("invalid Telegram RPC frame size %d", size)
	}
	var head []byte
	if budget != nil && size > maxPooledBufferSize {
		// Only proxy answers can use a frame this large. Check the target
		// before allocating an unpooled buffer for the body.
		var err error
		head, err = m.readFramePrefix(int(size))
		if err != nil {
			return ownedBuffer{}, rpcFramePrefix{}, err
		}
		packet := head[4:]
		var attached bool
		if le.Uint32(packet) == rpcProxyAns {
			m.streamMu.Lock()
			attached = m.streams[le.Uint64(packet[8:])] != nil
			m.streamMu.Unlock()
		}
		if !attached {
			return m.discardFrame(int(size), head)
		}
	}
	var frame ownedBuffer
	var data []byte
	if budget != nil && int(size) <= len(m.smallFrame) {
		data = m.smallFrame[:size]
	} else {
		var err error
		frame, err = borrowBuffer(int(size), budget)
		if errors.Is(err, errBufferBudget) {
			return m.discardFrame(int(size), head)
		}
		if err != nil {
			return ownedBuffer{}, rpcFramePrefix{}, err
		}
		data = frame.data
	}
	copy(data, m.readHeader[:])
	start := len(m.readHeader)
	if head != nil {
		start += copy(data[start:], head)
	}
	if _, err := io.ReadFull(m.reader, data[start:]); err != nil {
		frame.discard()
		return ownedBuffer{}, rpcFramePrefix{}, err
	}
	if int32(le.Uint32(data[4:])) != m.readSeq || crc32.ChecksumIEEE(data[:size-4]) != le.Uint32(data[size-4:]) {
		frame.discard()
		return ownedBuffer{}, rpcFramePrefix{}, errRPCFrame
	}
	m.readSeq++
	if frame.data == nil {
		return frame, rpcFramePrefix{body: data[8 : size-4], size: int(size) - rpcFrameOverhead}, nil
	}
	return frame, rpcFramePrefix{}, nil
}

func (m *middleConn) readFramePrefix(size int) ([]byte, error) {
	head := m.discardHead[:min(size-8, len(m.discardHead))]
	if _, err := io.ReadFull(m.reader, head); err != nil {
		return nil, err
	}
	// A sequence mismatch is terminal. Reject it before reading the payload.
	if int32(le.Uint32(head)) != m.readSeq {
		return nil, errRPCFrame
	}
	return head, nil
}

func (m *middleConn) discardFrame(size int, head []byte) (ownedBuffer, rpcFramePrefix, error) {
	if head == nil {
		var err error
		head, err = m.readFramePrefix(size)
		if err != nil {
			return ownedBuffer{}, rpcFramePrefix{}, err
		}
	}
	crc := crc32.Update(crc32.ChecksumIEEE(m.readHeader[:]), crc32.IEEETable, head)
	for remaining := size - 8 - len(head); remaining > 0; {
		if m.discardBuffer == nil {
			m.discardBuffer = make([]byte, 4096)
		}
		chunk := m.discardBuffer[:min(remaining, len(m.discardBuffer))]
		if _, err := io.ReadFull(m.reader, chunk); err != nil {
			return ownedBuffer{}, rpcFramePrefix{}, err
		}
		crc = crc32.Update(crc, crc32.IEEETable, chunk)
		remaining -= len(chunk)
	}
	if _, err := io.ReadFull(m.reader, m.discardTail[:]); err != nil {
		return ownedBuffer{}, rpcFramePrefix{}, err
	}
	if le.Uint32(m.discardTail[:]) != crc {
		return ownedBuffer{}, rpcFramePrefix{}, errRPCFrame
	}
	m.readSeq++
	return ownedBuffer{}, rpcFramePrefix{body: head[4:], size: size - rpcFrameOverhead}, nil
}

type cbcReader struct {
	source     io.Reader
	decrypt    cipher.BlockMode
	block      [16 * aes.BlockSize]byte
	pending    []byte
	bulkRecent bool
}

func (r *cbcReader) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	const bulkReadSize = 4 << 10
	// RPC reads the length, then the body. Keep the length and the final
	// partial-block reads from resetting the hint left by the body read.
	if len(dst) >= bulkReadSize {
		r.bulkRecent = true
	} else if len(dst) >= aes.BlockSize && len(dst) <= len(r.block)+aes.BlockSize {
		r.bulkRecent = false
	}
	if len(r.pending) == 0 {
		aligned := len(dst) / aes.BlockSize * aes.BlockSize
		if aligned > 0 {
			if aligned >= bulkReadSize {
				if buffered, ok := r.source.(*bufio.Reader); ok {
					n := min(aligned, buffered.Buffered()) &^ (len(r.block) - 1)
					if n >= 2<<10 {
						// Keep full batches in the fast path and decrypt buffered
						// ciphertext directly into dst. Both operations stay within
						// Buffered(), so they cannot read or return a wire error.
						ciphertext, _ := buffered.Peek(n)
						r.decrypt.CryptBlocks(dst[:n], ciphertext)
						_, _ = buffered.Discard(n)
						return n, nil
					}
				}
			}
			if _, err := io.ReadFull(r.source, dst[:aligned]); err != nil {
				return 0, err
			}
			r.decrypt.CryptBlocks(dst[:aligned], dst[:aligned])
			return aligned, nil
		}
		size := aes.BlockSize
		if _, err := io.ReadFull(r.source, r.block[:size]); err != nil {
			return 0, err
		}
		// A short read must work with a single ciphertext block. Decrypt a
		// full batch only when the remaining blocks are already buffered.
		if !r.bulkRecent {
			if buffered, ok := r.source.(*bufio.Reader); ok && buffered.Buffered() >= len(r.block)-size {
				if _, err := io.ReadFull(buffered, r.block[size:]); err != nil {
					return 0, err
				}
				size = len(r.block)
			}
		}
		plain := r.block[:size]
		r.decrypt.CryptBlocks(plain, plain)
		r.pending = plain
	}
	n := copy(dst, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}
