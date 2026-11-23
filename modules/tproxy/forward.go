package tproxy

import (
	"errors"
	"io"
	"net/netip"
	"sync"
	"time"
)

const (
	rpcExtTCP       uint32 = 0x1000
	rpcObfuscated   uint32 = 0x20000
	rpcIntermediate uint32 = 0x20000000
	rpcAbridged     uint32 = 0x40000000
	rpcQuickAck     uint32 = 0x80000000
	rpcPlainMTProto uint32 = 2
)

func forward(conn *proxyPipe, client *obfuscatedConn, stream *middleStream, first transportPacket, quickAck bool) error {
	middle := stream.middle
	var sent bool
	defer func() { stream.finish(sent) }()
	flags := rpcExtTCP | rpcObfuscated
	if client.tag == abridged {
		flags |= rpcAbridged
	} else {
		flags |= rpcIntermediate
	}
	// The WEB relay handed streams to MTProxy over loopback in the C setup.
	loopback := netip.AddrFrom4([4]byte{127, 0, 0, 1}).As16()
	proxyIP := middle.ourIP.As16()
	var writeMu sync.Mutex
	writeClient := func(packet []byte, offset int, ack uint32) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if packet == nil {
			return client.writer.writeQuickAck(client.tag, ack)
		}
		return client.writer.writePacketAt(client.tag, packet, offset)
	}
	up := func() error {
		packet, quick := first, quickAck
		first = transportPacket{}
		var request middleWrite
		var prefix [middleProxyRequestBytes]byte
		le.PutUint32(prefix[:], rpcProxyReq)
		le.PutUint64(prefix[8:16], stream.id)
		copy(prefix[16:32], loopback[:])
		copy(prefix[36:52], proxyIP[:])
		le.PutUint32(prefix[52:], 443)
		for {
			body := packet.payload()
			var writeErr error
			if ping := client.pingPayload(body); ping != nil {
				le.PutUint32(ping, rpcPong)
				writeErr = writeClient(ping, 0, 0)
			} else {
				plain, err := checkMTProtoPacket(body)
				if err != nil {
					packet.release()
					return err
				}
				packetFlags := flags | plain
				if quick {
					packetFlags |= rpcQuickAck
				}
				le.PutUint32(prefix[4:], packetFlags)
				writeErr = stream.send(&request, prefix[:], packet, conn.output.done)
				sent = sent || writeErr == nil
			}
			packet.release()
			packet = transportPacket{}
			if writeErr != nil {
				return writeErr
			}
			var err error
			packet, quick, err = client.readPacket(middle.budget)
			if err != nil {
				return err
			}
		}
	}
	upDone := make(chan error, 1)
	stopDown := make(chan struct{})
	go func() {
		err := up()
		_ = conn.Close()
		upDone <- err
		close(stopDown)
	}()
	down := func() error {
		for {
			select {
			case <-stopDown:
				return nil
			case packet, ok := <-stream.packets:
				if !ok {
					return io.EOF
				}
				err := writeClient(packet.frame.data, 8+rpcProxyAnswerHeader, packet.ack)
				stream.release(packet)
				if err != nil {
					return err
				}
			}
		}
	}
	downErr := down()
	_ = conn.Close()
	upErr := <-upDone
	if downErr != nil {
		return downErr
	}
	return upErr
}

func checkMTProtoPacket(body []byte) (uint32, error) {
	if len(body) >= 28 {
		if le.Uint64(body) != 0 {
			if len(body) >= 56 {
				return 0, nil
			}
		} else if size := le.Uint32(body[16:]); size >= 20 && size <= uint32(len(body)-20) {
			switch le.Uint32(body[20:]) {
			case 0x60469778, 0xbe7e8ef1, 0xd712e4be, 0xf5045f1f:
				return rpcPlainMTProto, nil
			}
		}
	}
	return 0, errors.New("invalid MTProto message")
}
