package tproxy

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

const (
	abridged           uint32 = 0xefefefef
	intermediate       uint32 = 0xeeeeeeee
	paddedIntermediate uint32 = 0xdddddddd
	maxTransportPacket        = 2 << 20
	transportPingSize         = 12
	maxPaddedPingSize         = transportPingSize + 15
)

var (
	errInvalidObfuscatedHandshake = errors.New("invalid MTProxy handshake")
	errHandshakeReplay            = errors.New("MTProxy handshake replay window rejected the stream")
)

// See https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation.
type obfuscatedConn struct {
	reader      io.Reader
	readHeader  [4]byte
	shortPacket [maxPaddedPingSize]byte
	writer      transportWriter
	tag         uint32
	dc          int16
}

func acceptObfuscated(conn io.ReadWriter, secret [16]byte, replays *handshakeReplays) (obfuscatedConn, error) {
	var header [64]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return obfuscatedConn{}, err
	}
	material := [48]byte(header[8:56])
	read := obfuscationStream(material[:], secret[:])
	read.XORKeyStream(header[:], header[:])
	tag := binary.LittleEndian.Uint32(header[56:])
	switch tag {
	case abridged, intermediate, paddedIntermediate:
	default:
		return obfuscatedConn{}, errInvalidObfuscatedHandshake
	}
	if !replays.remember(sha256.Sum256(material[:])) {
		return obfuscatedConn{}, errHandshakeReplay
	}
	return obfuscatedConn{
		reader: &cipher.StreamReader{S: read, R: conn},
		writer: transportWriter{stream: reverseObfuscationStream(&material, secret[:]), destination: conn},
		tag:    tag,
		dc:     int16(binary.LittleEndian.Uint16(header[60:])),
	}, nil
}

func obfuscationStream(material, secret []byte) cipher.Stream {
	var input [48]byte
	copy(input[:32], material[:32])
	copy(input[32:], secret)
	key := sha256.Sum256(input[:])
	return newTransportCTR(key, [16]byte(material[32:]))
}

func reverseObfuscationStream(material *[48]byte, secret []byte) cipher.Stream {
	var reversed [48]byte
	for i := range reversed {
		reversed[i] = material[len(reversed)-1-i]
	}
	return obfuscationStream(reversed[:], secret)
}

func readTransportPacket(reader io.Reader, tag uint32) ([]byte, bool, error) {
	client := obfuscatedConn{reader: reader, tag: tag}
	packet, quick, err := client.readPacket(nil)
	return packet.payload(), quick, err
}

type transportPacket struct {
	ownedBuffer
	offset int
}

func (p transportPacket) payload() []byte { return p.data[p.offset:] }

func (c *obfuscatedConn) readPacket(budget *bufferBudget) (transportPacket, bool, error) {
	size, quickAck, err := transportPacketSize(c.reader, c.tag, &c.readHeader)
	if err != nil {
		return transportPacket{}, false, err
	}
	var packet transportPacket
	if budget != nil && size <= maxPaddedPingSize {
		// A short incoming packet is handled synchronously by the reader.
		packet.data = c.shortPacket[:size]
	} else {
		storage := int(size)
		if budget != nil && size&^3 >= middleInPlacePayload {
			// The RPC checksum has room for the discarded transport padding.
			packet.offset = middleRequestHeadroom
			storage = rpcPaddedSize(rpcFrameOverhead + middleProxyRequestBytes + int(size&^3))
		}
		packet.ownedBuffer, err = borrowBuffer(storage, budget)
		if err != nil {
			return transportPacket{}, false, err
		}
	}
	if _, err := io.ReadFull(c.reader, packet.data[packet.offset:packet.offset+int(size)]); err != nil {
		packet.discard()
		return transportPacket{}, false, err
	}
	packet.data = packet.data[:packet.offset+int(size&^3)]
	return packet, quickAck, nil
}

func (c *obfuscatedConn) pingPayload(body []byte) []byte {
	limit := transportPingSize
	if c.tag == paddedIntermediate {
		limit = maxPaddedPingSize
	}
	if len(body) < transportPingSize || len(body) > limit || le.Uint32(body) != rpcPing {
		return nil
	}
	return body[:transportPingSize]
}

func transportPacketSize(reader io.Reader, tag uint32, header *[4]byte) (uint32, bool, error) {
	var size uint32
	var quickAck bool
	switch tag {
	case abridged:
		if _, err := io.ReadFull(reader, header[:1]); err != nil {
			return 0, false, err
		}
		quickAck = header[0]&0x80 != 0
		size = uint32(header[0] & 0x7f)
		if size == 0x7f {
			if _, err := io.ReadFull(reader, header[:3]); err != nil {
				return 0, false, err
			}
			size = uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16
			if size < 0x7f {
				return 0, false, errors.New("noncanonical abridged packet length")
			}
		}
		size *= 4
	default:
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return 0, false, err
		}
		size = binary.LittleEndian.Uint32(header[:])
		quickAck = size&0x80000000 != 0
		size &= 0x7fffffff
	}

	payload := size &^ 3
	if payload < 4 || payload > maxTransportPacket || (tag != paddedIntermediate && payload != size) {
		return 0, false, errors.New("invalid MTProto packet size")
	}
	return size, quickAck, nil
}

type transportWriter struct {
	stream      cipher.Stream
	destination io.Writer
	writeErr    error // A failed write leaves the cipher and destination out of sync.
	buffer      packetBuffer
	ack         [4 + 8 + 3]byte // Length, padded quick ACK, and up to three padding bytes.
	padding     [64]byte
	paddingLeft uint8
}

func (w *transportWriter) writePacket(tag uint32, body []byte) error {
	return w.writePacketAt(tag, body, 0)
}

func (w *transportWriter) writeQuickAck(tag, token uint32) error {
	if w.writeErr != nil {
		return w.writeErr
	}
	token |= 0x80000000
	wire := w.ack[:4]
	switch tag {
	case abridged:
		binary.BigEndian.PutUint32(wire, token)
	case paddedIntermediate:
		binary.LittleEndian.PutUint32(w.ack[4:], 0xffffffff)
		binary.LittleEndian.PutUint32(w.ack[8:], token)
		return w.writePacketAt(tag, w.ack[:12], 4)
	default:
		binary.LittleEndian.PutUint32(wire, token)
	}
	return w.write(wire)
}

func (w *transportWriter) writePacketAt(tag uint32, packet []byte, offset int) error {
	if w.writeErr != nil {
		return w.writeErr
	}
	body := packet[offset:]
	if len(body) == 0 || len(body) > maxTransportPacket || len(body)%4 != 0 {
		return errors.New("invalid Telegram packet size")
	}
	var header [4]byte
	prefix := header[:]
	var padding []byte
	if tag == abridged {
		words := uint32(len(body) / 4)
		if words < 0x7f {
			header[0] = byte(words)
			prefix = header[:1]
		} else {
			binary.LittleEndian.PutUint32(header[:], 0x7f|words<<8)
		}
	} else {
		if tag == paddedIntermediate {
			padding = w.nextPadding()
		}
		binary.LittleEndian.PutUint32(header[:], uint32(len(body)+len(padding)))
	}
	if offset >= len(prefix) && len(padding) <= cap(packet)-len(packet) {
		wire := packet[offset-len(prefix) : len(packet)+len(padding)]
		copy(wire, prefix)
		copy(wire[len(prefix)+len(body):], padding)
		return w.write(wire)
	}
	wire, pooled := w.buffer.acquire(len(prefix) + len(body) + len(padding))
	if pooled != nil {
		defer pooled.release()
	}
	next := copy(wire, prefix)
	next += copy(wire[next:], body)
	copy(wire[next:], padding)
	return w.write(wire)
}

func (w *transportWriter) nextPadding() []byte {
	if w.paddingLeft == 0 {
		rand.Read(w.padding[:])
		w.paddingLeft = uint8(len(w.padding))
	}
	w.paddingLeft -= 4
	i := int(w.paddingLeft)
	// Give each packet an unused group of three bytes and a separate length byte.
	return w.padding[i : i+int(w.padding[i+3]&3)]
}

func (w *transportWriter) write(wire []byte) error {
	w.stream.XORKeyStream(wire, wire)
	if err := writeFull(w.destination, wire); err != nil {
		w.writeErr = err
		return err
	}
	return nil
}

type packetBuffer []byte

const retainedPacketBytes = 16 << 10

type pooledPacket struct {
	buffer []byte
	pool   *sync.Pool
}

func (p *pooledPacket) release() { p.pool.Put(p) }

func packetPool(size int) *sync.Pool {
	pool := new(sync.Pool)
	pool.New = func() any { return &pooledPacket{buffer: make([]byte, size), pool: pool} }
	return pool
}

var (
	packet32K  = packetPool(32 << 10)
	packet64K  = packetPool(64 << 10)
	packet128K = packetPool(128 << 10)
)

func (b *packetBuffer) acquire(size int) ([]byte, *pooledPacket) {
	// Keep small frames per stream and share media buffers between active writers.
	var pool *sync.Pool
	switch {
	case size <= retainedPacketBytes:
		if cap(*b) < size {
			*b = make([]byte, size)
		}
		return (*b)[:size], nil
	case size <= 32<<10:
		pool = packet32K
	case size <= 64<<10:
		pool = packet64K
	case size <= 128<<10:
		pool = packet128K
	default:
		return make([]byte, size), nil
	}
	packet := pool.Get().(*pooledPacket)
	return packet.buffer[:size], packet
}

func writeFull(writer io.Writer, data []byte) error {
	n, err := writer.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}
