package tproxy

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"testing/iotest"
	"time"
)

func TestMiddleRPCIndependentWireVector(t *testing.T) {
	decode := func(value string) []byte {
		t.Helper()
		data, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	// Independently encoded with Python struct/zlib and OpenSSL AES-256-CBC.
	// The nonce is cleartext. The handshake, answer + ACK, and PONG are
	// separate encrypted flushes with four-byte padding markers (4, 8, and
	// 8 padding bytes respectively). CBC chaining continues across flushes.
	want := decode("2c000000feffffffaa87cb7a443322110100000003020168606162636465666768696a6b6c6d6e6f2ea05695" +
		"71a9bfb1ac01242b71a61a385b6d303aa0c529fc0fbdaa9088b87115053eb5e0f6c60cf381fc417effb02580e0fe54eb" +
		"2f8e365d7ec7b6e9b7cc60c18f3c6f45b3561030d19fa98befc407def5e094b2eefc06814085aa0e750fff971a87b368" +
		"2e131e9cfb03f3deedb90a0cec25936cdfd4389b811143afaf06fb479550b2a6067bcf1bf3e7b50d2b0608084e77eb34" +
		"526a85a48acd4de8ea79a6296cfd6b3726c4d1df6291d38a83b5e33890d480deb36c11a6eb0ebb9375afa4f750eb2bd7" +
		"3a0ace9e680c7e9a9d66fb7c1c1186deada032ae64ff5c254301902ce0bc5a6ec17c5088fa0ee30e5a392f510b7ea241" +
		"8a44bb3b632fff151a230bcde1eb334129ce802e08e153852c732e112298333f43409a3c1007c418473f62337271150c" +
		"12af14f2d2acebbf904868f8acbf9166823e1d7324221841ab77d4443178fdbffac396216be133417801ca4776c1c4b8" +
		"e6c0cf6dc21439d2cf53b7b6668b8cd14b10eb72346811a82e58b5384a4251ec234774f451283561aef98bd77e2b7290" +
		"1cf6da8f129ee1bcb63912db291817f60730fb69c4bc37015518b56b7436097c")
	nonce := decode("aa87cb7a443322110100000003020168606162636465666768696a6b6c6d6e6f")
	handshake := decode("f5ee827600000000000102030405060708090a0b0c0d0e0f1011121314151617")
	answer := decode("0dda0344000000008877665544332211")
	for i := range 272 {
		answer = append(answer, byte(i^(i>>8)))
	}
	ack := decode("9b40ac3b887766554433221178563412")
	pong := decode("a7ea30848070605040302010")
	var key [32]byte
	var iv [16]byte
	for i := range key {
		key[i] = byte(i)
	}
	for i := range iv {
		iv[i] = byte(0x10 + i)
	}

	for _, fragmented := range []bool{false, true} {
		name := "buffered"
		if fragmented {
			name = "fragmented"
		}
		t.Run(name, func(t *testing.T) {
			var stream io.Reader = bytes.NewReader(want)
			if fragmented {
				stream = iotest.OneByteReader(stream)
			}
			buffered := bufio.NewReader(stream)
			reader := &middleConn{reader: buffered, readSeq: -2}
			if got, err := reader.read(rpcHandshakePacket); err != nil || !bytes.Equal(got, nonce) {
				t.Fatalf("nonce = %x, error %v", got, err)
			}
			reader.reader = &cbcReader{source: buffered, decrypt: newRPCDecrypter(key, iv)}
			if got, err := reader.read(rpcHandshakePacket); err != nil || !bytes.Equal(got, handshake) {
				t.Fatalf("handshake = %x, error %v", got, err)
			}
			budget := new(bufferBudget)
			for i, expected := range [][]byte{answer, ack, pong} {
				frame, prefix, err := reader.readFrame(budget, maxRPCPacket)
				got := prefix.body
				if frame.data != nil {
					got = frame.data[8 : len(frame.data)-4]
				}
				matches := bytes.Equal(got, expected)
				frame.release()
				if err != nil || !matches {
					t.Fatalf("frame %d decoded incorrectly, size %d, error %v", i, len(got), err)
				}
			}
			if reader.readSeq != 3 || budget.used.Load() != 0 {
				t.Fatalf("next sequence %d, outstanding bytes %d", reader.readSeq, budget.used.Load())
			}
			var padding [8]byte
			if _, err := io.ReadFull(reader.reader, padding[:]); err != nil || padding != [8]byte{4, 0, 0, 0, 4} {
				t.Fatalf("final flush padding = %x, error %v", padding, err)
			}
		})
	}

	t.Run("emitted bytes", func(t *testing.T) {
		conn, peer := net.Pipe()
		defer peer.Close()
		if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		block, err := aes.NewCipher(key[:])
		if err != nil {
			t.Fatal(err)
		}
		writer := &middleConn{conn: conn, writeSeq: -2, stats: new(backendStats)}
		write := func() error {
			if err := writer.write(nonce); err != nil {
				return err
			}
			writer.encrypt = cipher.NewCBCEncrypter(block, iv[:])
			if err := writer.write(handshake); err != nil {
				return err
			}
			if err := writer.writeBatch([]*middleWrite{{body: answer}, {body: ack}}, rpcFrameSize(answer)+rpcFrameSize(ack)); err != nil {
				return err
			}
			return writer.writeBatch([]*middleWrite{{body: pong}}, rpcFrameSize(pong))
		}
		done := make(chan error, 1)
		go func() {
			defer conn.Close()
			done <- write()
		}()
		got, err := io.ReadAll(peer)
		writeErr := <-done
		if err != nil || writeErr != nil || !bytes.Equal(got, want) {
			t.Fatalf("wire mismatch, size %d (want %d), read error %v, write error %v", len(got), len(want), err, writeErr)
		}
	})
}
