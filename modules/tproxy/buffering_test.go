package tproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"testing/iotest"
	"testing/synctest"
	"time"

	"go.uber.org/zap"
)

func TestRPCHandshakeRejectsLargeFrameBeforeReadingPayload(t *testing.T) {
	var encoder middleConn
	valid := encoder.appendFrame(nil, rpcHandshakePacket, make([]byte, rpcHandshakeBody))
	decoder := &middleConn{reader: bytes.NewReader(valid)}
	if payload, err := decoder.read(rpcHandshakePacket); err != nil || len(payload) != rpcHandshakeBody {
		t.Fatalf("valid handshake frame returned %d bytes, error %v", len(payload), err)
	}
	reader := bytes.NewReader(le.AppendUint32(nil, maxRPCPacket))
	decoder.reader = reader
	if _, err := decoder.read(rpcHandshakePacket); err == nil || !strings.Contains(err.Error(), "frame size") {
		t.Fatalf("oversized handshake length did not fail at the header: %v", err)
	}
}

func TestCBCReaderAcrossBufferedAndFragmentedReads(t *testing.T) {
	var key [32]byte
	var iv [aes.BlockSize]byte
	plain := make([]byte, 64<<10)
	for i := range plain {
		plain[i] = byte(i ^ (i >> 8))
	}
	wire := make([]byte, len(plain)+7)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(wire[:len(plain)], plain)
	for _, source := range []io.Reader{
		bufio.NewReaderSize(bytes.NewReader(wire), 512),
		bufio.NewReaderSize(bytes.NewReader(wire), (16<<10)-1),
		bufio.NewReaderSize(iotest.OneByteReader(bytes.NewReader(wire)), 512),
	} {
		reader := &cbcReader{source: source, decrypt: newRPCDecrypter(key, iv)}
		if n, err := reader.Read(nil); n != 0 || err != nil || len(reader.pending) != 0 {
			t.Fatalf("zero-byte Read consumed ciphertext or returned an error: %d, %v", n, err)
		}
		got := make([]byte, len(plain)+4)
		from := 0
		for _, to := range []int{4, 44, 47, 301, 513, 4609, 4613, 4653, 35995, 36004} {
			if _, err := io.ReadFull(reader, got[from:to]); err != nil {
				t.Fatalf("CBC read %d to %d failed: %v", from, to, err)
			}
			from = to
		}
		if n, err := io.ReadFull(reader, got[from:]); n != len(plain)-from || err != io.ErrUnexpectedEOF {
			t.Fatalf("truncated ciphertext returned %d bytes, error %v", n, err)
		}
		if !bytes.Equal(got[:len(plain)], plain) {
			t.Fatal("fragmented CBC reads changed the plaintext")
		}
	}
}

func TestRPCReadDeadlineCoversPartialFrame(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn, peer := net.Pipe()
		defer conn.Close()
		defer peer.Close()
		key, iv := [32]byte{1}, [aes.BlockSize]byte{2}
		block, err := aes.NewCipher(key[:])
		if err != nil {
			t.Fatal(err)
		}
		encoder := middleConn{encrypt: cipher.NewCBCEncrypter(block, iv[:])}
		const frameSize = 2 * aes.BlockSize
		body := make([]byte, frameSize-rpcFrameOverhead)
		le.PutUint32(body, rpcPong)
		var wire []byte
		for range 3 {
			wire = encoder.appendFrame(wire, rpcFrameSize(body), body)
		}
		encoder.encrypt.CryptBlocks(wire, wire)

		decoder := middleConn{conn: conn, budget: &bufferBudget{}, readSource: middleReadSource{conn: conn}}
		decoder.reader = &cbcReader{
			source:  bufio.NewReader(&decoder.readSource),
			decrypt: newRPCDecrypter(key, iv),
		}
		result := make(chan error, 1)
		go func() { result <- decoder.readStreams() }()
		if _, err := peer.Write(wire[:2*frameSize]); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if decoder.readSeq != 2 {
			t.Fatalf("decoded %d of 2 buffered frames", decoder.readSeq)
		}
		time.Sleep(middleReadTimeout - time.Second)
		if _, err := peer.Write(wire[2*frameSize : 2*frameSize+aes.BlockSize]); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-result:
			if !os.IsTimeout(err) || decoder.readSeq != 2 {
				t.Fatalf("partial frame returned %v, sequence %d", err, decoder.readSeq)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("read deadline was extended within the same frame")
		}
	})
}

func TestRPCWriterBatchesReadyFrames(t *testing.T) {
	testRPCWriter(t, []int{4096, 4096}, &bufferBudget{}, []error{nil, nil}, 1)
}

func TestRPCWriterBackpressuresDataWithoutUsingControlReserve(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sender, receiver := net.Pipe()
		defer receiver.Close()
		writer := &middleConn{
			conn: sender, done: make(chan struct{}), writes: make(chan *middleWrite, middleWriteQueue),
			streams: make(map[uint64]*middleStream), stats: &backendStats{}, budget: &bufferBudget{},
		}
		defer writer.close()
		const dataSlots = middleWriteQueue - middleControlSlots
		results := make(chan error, dataSlots-1)
		queued := []byte{1, 2, 3, 4}
		for range dataSlots - 1 {
			if err := writer.queueWrite(&middleWrite{body: queued, result: results}); err != nil {
				t.Fatal(err)
			}
		}
		body := bytes.Repeat([]byte{8}, 4096)
		start := func(id uint64, client *proxyPipe) (<-chan error, int64) {
			stream := writer.attach(id, client)
			payload, err := borrowBuffer(len(body), writer.budget)
			if err != nil {
				t.Fatal(err)
			}
			copy(payload.data, body)
			result := make(chan error, 1)
			go func() {
				var request middleWrite
				err := stream.send(&request, nil, transportPacket{ownedBuffer: payload}, client.output.done)
				payload.release()
				result <- err
			}()
			return result, int64(cap(payload.data))
		}
		relay, client := newProxyPipe()
		defer relay.Close()
		canceled, canceledClient := newProxyPipe()
		defer canceled.Close()
		queuedCanceled, queuedCanceledClient := newProxyPipe()
		defer queuedCanceled.Close()
		queuedCanceledResult, queuedCanceledCost := start(3, queuedCanceledClient)
		synctest.Wait()
		result, cost := start(1, client)
		canceledResult, canceledCost := start(2, canceledClient)
		synctest.Wait()
		select {
		case err := <-result:
			t.Fatalf("burst dropped the stream before upstream could make progress: %v", err)
		default:
		}
		if len(writer.writes) != dataSlots || writer.budget.used.Load() != cost+canceledCost+queuedCanceledCost {
			t.Fatal("the waiting frame used a control slot or changed its budget charge")
		}
		_ = canceled.Close()
		_ = queuedCanceled.Close()
		synctest.Wait()
		select {
		case err := <-canceledResult:
			if err != net.ErrClosed || writer.budget.used.Load() != cost+queuedCanceledCost {
				t.Fatalf("canceled stream got %v with %d bytes still reserved", err, writer.budget.used.Load())
			}
		default:
			t.Fatal("canceled stream still waiting for the stalled upstream")
		}
		select {
		case err := <-queuedCanceledResult:
			t.Fatalf("queued stream released borrowed storage before the writer processed it: %v", err)
		default:
		}
		if err := writer.sendControl(rpcPong, 42); err != nil {
			t.Fatal(err)
		}
		go writer.writeStreams()
		reader := &middleConn{reader: receiver}
		for range dataSlots - 1 {
			if got, err := reader.read(maxRPCPacket); err != nil || !bytes.Equal(got, queued) {
				t.Fatalf("queued frame changed: %x, %v", got, err)
			}
		}
		if got, err := reader.read(maxRPCPacket); err != nil || !bytes.Equal(got, le.AppendUint64(le.AppendUint32(nil, rpcPong), 42)) {
			t.Fatalf("required control frame changed: %x, %v", got, err)
		}
		if got, err := reader.read(maxRPCPacket); err != nil || !bytes.Equal(got, body) {
			t.Fatalf("backpressured frame changed: %d bytes, %v", len(got), err)
		}
		if err := <-queuedCanceledResult; err != net.ErrClosed {
			t.Fatalf("canceled queued frame got %v", err)
		}
		if err := <-result; err != nil || writer.stats.writeRejected.Load() != 0 || writer.budget.used.Load() != 0 {
			t.Fatalf("backpressured write result %v, rejections %d, budget %d", err, writer.stats.writeRejected.Load(), writer.budget.used.Load())
		}
	})
}

func TestRPCWriterReservesRequiredControlsAndClosesOnOverflow(t *testing.T) {
	for _, kind := range []string{"close", "pong"} {
		t.Run(kind, func(t *testing.T) {
			conn, peer := net.Pipe()
			defer peer.Close()
			writer := &middleConn{
				conn: conn, done: make(chan struct{}), writes: make(chan *middleWrite, middleWriteQueue),
				streams: make(map[uint64]*middleStream), stats: &backendStats{},
			}
			defer writer.close()
			const dataSlots = middleWriteQueue - middleControlSlots
			results := make(chan error, dataSlots)
			for range dataSlots {
				if err := writer.queueWrite(&middleWrite{body: []byte{1, 2, 3, 4}, result: results}); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.sendControl(rpcPing, 42); err != errBufferBudget {
				t.Fatalf("periodic ping used the required control reserve: %v", err)
			}
			for i := range middleControlSlots {
				if err := writer.notifyClosed(uint64(i + 1)); err != nil {
					t.Fatal(err)
				}
			}
			if _, ready := writer.load(); !ready || writer.stats.controlOverflows.Load() != 0 {
				t.Fatal("admitting the last reserved control closed the connection")
			}
			stream := writer.attach(1000, conn)
			other := writer.attach(1001, conn)
			if kind == "close" {
				stream.finish(true)
			} else {
				var ping [rpcControlBody]byte
				le.PutUint32(ping[:], rpcPing)
				le.PutUint64(ping[4:], 42)
				writer.handleControl(ping[:])
			}
			select {
			case <-writer.done:
			default:
				t.Fatal("the upstream connection stayed open after losing a required control frame")
			}
			if writer.stats.controlOverflows.Load() != 1 || !other.detached.Load() {
				t.Fatal("overflow was not counted or streams were left attached")
			}
			writer.writeStreams()
			for range dataSlots {
				select {
				case err := <-results:
					if err != net.ErrClosed {
						t.Fatalf("queued data got %v after the socket closed", err)
					}
				default:
					t.Fatal("a queued data frame was left without a result")
				}
			}
		})
	}
}

func TestRPCWriterRetriesIndividualFramesUnderPressure(t *testing.T) {
	budget := &bufferBudget{shared: func(size int) bool { return size <= 16<<10 }}
	testRPCWriter(t, []int{4096, 16 << 10, 0, 4096}, budget, []error{nil, errBufferBudget, nil, nil}, 3)
}

func TestRPCWriterReusesLargeBatchStorageUnderPressure(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	budget := &bufferBudget{}
	large, err := borrowBuffer(rpcPaddedSize(middleRequestHeadroom+middleInPlacePayload+4), budget)
	if err != nil {
		t.Fatal(err)
	}
	defer large.release()
	budget.shared = func(delta int) bool { return delta <= 0 }
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	var iv [aes.BlockSize]byte
	writer := &middleConn{
		conn: conn, encrypt: cipher.NewCBCEncrypter(block, iv[:]), budget: budget,
		done: make(chan struct{}), writes: make(chan *middleWrite, middleWriteQueue), stats: &backendStats{},
	}
	reader := &middleConn{reader: &cbcReader{source: peer, decrypt: cipher.NewCBCDecrypter(block, iv[:])}}
	var prefix [middleProxyRequestBytes]byte
	le.PutUint32(prefix[:], rpcProxyReq)
	body := large.data[middleRequestHeadroom : middleRequestHeadroom+middleInPlacePayload]
	for i := range body {
		body[i] = byte(i>>8 ^ i)
	}
	want := append(append([]byte(nil), prefix[:]...), body...)
	result := make(chan error, 1)
	if err := writer.queueWrite(&middleWrite{prefix: prefix[:], body: body, wire: large.data[:0], result: result}); err != nil {
		t.Fatal(err)
	}
	if err := writer.sendControl(rpcPong, 42); err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		writer.writeStreams()
	}()
	defer func() {
		writer.close()
		<-finished
	}()
	for _, expected := range [][]byte{want, le.AppendUint64(le.AppendUint32(nil, rpcPong), 42)} {
		if got, err := reader.read(maxRPCPacket); err != nil || !bytes.Equal(got, expected) {
			t.Fatalf("unexpected RPC frame length %d, error %v", len(got), err)
		}
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	writer.close()
	<-finished
	if frames, batches, denied := writer.stats.writeFrames.Load(), writer.stats.writeBatches.Load(), budget.denied.Load(); frames != 2 || batches != 1 || denied != 0 {
		t.Fatalf("wrote %d frames in %d batches with %d denied reservations", frames, batches, denied)
	}
}

func TestRPCWriterReusesLargeTransportPacket(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
	}{
		{"threshold", middleInPlacePayload},
		{"maximum", maxTransportPacket},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix := bytes.Repeat([]byte{0x95}, middleProxyRequestBytes)
			payload := make([]byte, tc.size)
			for i := range payload {
				payload[i] = byte(i ^ (i >> 8))
			}
			input := append(le.AppendUint32(nil, uint32(len(payload)+3)), payload...)
			input = append(input, 0x11, 0x22, 0x33)
			client := obfuscatedConn{reader: bytes.NewReader(input), tag: paddedIntermediate}
			budget := &bufferBudget{}
			_, capacity := bufferClass(rpcPaddedSize(rpcFrameSize(prefix, payload)))
			budget.shared = func(delta int) bool {
				return delta <= 0 || budget.used.Load() <= int64(capacity)
			}
			packet, _, err := client.readPacket(budget)
			if err != nil {
				t.Fatal(err)
			}
			defer packet.release()
			if packet.offset != middleRequestHeadroom || !bytes.Equal(packet.payload(), payload) || budget.used.Load() != int64(capacity) {
				t.Fatal("incoming packet did not preserve the payload and reserve its RPC storage")
			}

			sender, receiver := net.Pipe()
			defer receiver.Close()
			_ = receiver.SetReadDeadline(time.Now().Add(3 * time.Second))
			block, err := aes.NewCipher(make([]byte, 32))
			if err != nil {
				t.Fatal(err)
			}
			var iv [aes.BlockSize]byte
			writer := &middleConn{
				conn: sender, encrypt: cipher.NewCBCEncrypter(block, iv[:]),
				done: make(chan struct{}), writes: make(chan *middleWrite, middleWriteQueue),
				streams: make(map[uint64]*middleStream), stats: &backendStats{}, budget: budget,
			}
			stream := writer.attach(1, sender)
			reader := &middleConn{reader: &cbcReader{source: receiver, decrypt: cipher.NewCBCDecrypter(block, iv[:])}}
			written, done := make(chan error, 1), make(chan struct{})
			var request middleWrite
			go func() {
				defer close(done)
				writer.writeStreams()
			}()
			go func() { written <- stream.send(&request, prefix, packet, nil) }()
			defer func() {
				writer.close()
				<-done
			}()
			body, err := reader.read(maxRPCPacket)
			if err != nil || !bytes.Equal(body, append(prefix, payload...)) {
				t.Fatalf("invalid large RPC frame, length %d, error %v", len(body), err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if request.body != nil || request.wire != nil {
				t.Fatal("completed RPC request retained the packet storage")
			}
			if err := writer.sendControl(rpcPing, 42); err != nil {
				t.Fatal(err)
			}
			body, err = reader.read(maxRPCPacket)
			want := le.AppendUint64(le.AppendUint32(nil, rpcPing), 42)
			if err != nil || !bytes.Equal(body, want) || budget.denied.Load() != 0 {
				t.Fatalf("next RPC frame or budget invalid: %x, error %v, denied %d", body, err, budget.denied.Load())
			}
		})
	}
}

func TestRPCWriterSkipsDetachedStreamWithoutBreakingBatch(t *testing.T) {
	sender, receiver := net.Pipe()
	defer receiver.Close()
	_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	var iv [aes.BlockSize]byte
	writer := &middleConn{
		conn: sender, encrypt: cipher.NewCBCEncrypter(block, iv[:]),
		done: make(chan struct{}), writes: make(chan *middleWrite, middleWriteQueue),
		streams: make(map[uint64]*middleStream), stats: &backendStats{}, budget: &bufferBudget{},
	}
	defer writer.close()
	reader := &middleConn{reader: &cbcReader{source: receiver, decrypt: cipher.NewCBCDecrypter(block, iv[:])}}
	first, retired, last := writer.attach(1, sender), writer.attach(2, sender), writer.attach(3, sender)
	for _, stream := range []*middleStream{first, retired, last} {
		body := bytes.Repeat([]byte{byte(stream.id)}, 4096)
		request := &middleWrite{body: body, result: stream.writeResult, stream: stream}
		if err := writer.queueWrite(request); err != nil {
			t.Fatal(err)
		}
	}
	var closeBody [rpcControlBody]byte
	le.PutUint32(closeBody[:], rpcCloseExt)
	le.PutUint64(closeBody[4:], retired.id)
	writer.handleControl(closeBody[:])
	if err := writer.queueWrite(&middleWrite{stream: retired, result: retired.writeResult}); err != net.ErrClosed {
		t.Fatalf("queued a request for a detached stream: %v", err)
	}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		writer.writeStreams()
	}()
	defer func() {
		writer.close()
		<-finished
	}()
	for _, stream := range []*middleStream{first, last} {
		body, err := reader.read(maxRPCPacket)
		if err != nil || !bytes.Equal(body, bytes.Repeat([]byte{byte(stream.id)}, 4096)) {
			t.Fatalf("unexpected frame for stream %d: %d bytes, %v", stream.id, len(body), err)
		}
	}
	for _, stream := range []*middleStream{first, retired, last} {
		var want error
		if stream == retired {
			want = net.ErrClosed
		}
		select {
		case got := <-stream.writeResult:
			if got != want {
				t.Fatalf("stream %d got %v, want %v", stream.id, got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("stream %d did not receive a write result", stream.id)
		}
	}
	if writer.stats.writeFrames.Load() != 2 || writer.stats.writeBatches.Load() != 1 || writer.budget.used.Load() != 0 {
		t.Fatal("detached requests changed batch accounting")
	}
}

func testRPCWriter(t *testing.T, sizes []int, budget *bufferBudget, wantErrors []error, wantBatches uint64) {
	t.Helper()
	sender, receiver := net.Pipe()
	defer receiver.Close()
	_ = receiver.SetReadDeadline(time.Now().Add(3 * time.Second))
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	var iv [aes.BlockSize]byte
	writer := &middleConn{
		conn: sender, encrypt: cipher.NewCBCEncrypter(block, iv[:]),
		done: make(chan struct{}), writes: make(chan *middleWrite, middleWriteQueue),
		stats: &backendStats{}, budget: budget,
	}
	defer writer.close()
	reader := &middleConn{reader: &cbcReader{source: receiver, decrypt: cipher.NewCBCDecrypter(block, iv[:])}}
	payloads := make([][]byte, len(sizes))
	results := make([]chan error, len(sizes))
	for i, size := range sizes {
		if size == 0 {
			payloads[i] = make([]byte, 12)
			le.PutUint32(payloads[i], rpcPing)
			le.PutUint64(payloads[i][4:], 42)
			if err := writer.sendControl(rpcPing, 42); err != nil {
				t.Fatal(err)
			}
			continue
		}
		payloads[i] = bytes.Repeat([]byte{byte(i + 1)}, size)
		results[i] = make(chan error, 1)
		if err := writer.queueWrite(&middleWrite{body: payloads[i], result: results[i]}); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan struct{})
	go func() {
		writer.writeStreams()
		close(done)
	}()
	t.Cleanup(func() {
		writer.close()
		<-done
	})
	var sent, rejected uint64
	for i, payload := range payloads {
		if wantErrors[i] != nil {
			rejected++
			continue
		}
		body, err := reader.read(maxRPCPacket)
		if err != nil || !bytes.Equal(body, payload) {
			t.Fatalf("invalid RPC frame %d, length %d, error %v", i, len(body), err)
		}
		sent++
	}
	for i, result := range results {
		if result != nil {
			if err := <-result; err != wantErrors[i] {
				t.Fatalf("RPC frame %d result %v, want %v", i, err, wantErrors[i])
			}
		}
	}
	if frames, batches := writer.stats.writeFrames.Load(), writer.stats.writeBatches.Load(); frames != sent || batches != wantBatches {
		t.Fatalf("wrote %d frames in %d batches", frames, batches)
	}
	if got := writer.stats.writeRejected.Load(); got != rejected {
		t.Fatalf("rejected %d frames, want %d", got, rejected)
	}
	if budget.used.Load() != 0 {
		t.Fatal("the RPC writer did not release its buffer budget")
	}
}

func TestRPCBudgetDropPreservesSequence(t *testing.T) {
	var encoder middleConn
	var prefix [16]byte
	le.PutUint32(prefix[:], rpcProxyAns)
	le.PutUint64(prefix[8:], 11)
	payload := bytes.Repeat([]byte{19}, 64<<10)
	wire := encoder.appendFrame(nil, rpcFrameSize(prefix[:], payload), prefix[:], payload)
	tail := []byte{1, 2, 3, 4}
	wire = encoder.appendFrame(wire, rpcFrameSize(prefix[:], tail), prefix[:], tail)
	decoder := &middleConn{reader: bytes.NewReader(wire)}
	budget := &bufferBudget{shared: func(int) bool { return false }}
	frame, dropped, err := decoder.readFrame(budget, maxRPCPacket)
	if err != nil || frame.data != nil || !bytes.Equal(dropped.body, prefix[:]) || dropped.size != len(prefix)+len(payload) || budget.used.Load() != 0 {
		t.Fatalf("unexpected dropped frame prefix %x, full size %d, error %v", dropped.body, dropped.size, err)
	}
	budget.shared = nil
	frame, dropped, err = decoder.readFrame(budget, maxRPCPacket)
	if err != nil || dropped.body != nil || !bytes.Equal(frame.data[8:len(frame.data)-4], append(prefix[:], tail...)) {
		t.Fatalf("next frame failed: %v", err)
	}
	frame.release()
	if budget.used.Load() != 0 {
		t.Fatal("released frame still charged to the budget")
	}
}

func TestRPCRejectsOutOfSequenceAnswerAtPrefix(t *testing.T) {
	const streamID = 11
	for _, tc := range []struct {
		name     string
		size     int
		attached bool
		refuse   bool
	}{
		{name: "attached large answer", size: 512 << 10, attached: true},
		{name: "late large answer", size: 512 << 10},
		{name: "answer without payload budget", size: 64 << 10, attached: true, refuse: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var prefix [rpcFrameHeader + rpcProxyAnswerHeader]byte
			le.PutUint32(prefix[:], uint32(tc.size))
			le.PutUint32(prefix[4:], 1)
			le.PutUint32(prefix[rpcFrameHeader:], rpcProxyAns)
			le.PutUint64(prefix[rpcFrameHeader+8:], streamID)
			decoder := &middleConn{reader: bytes.NewReader(prefix[:])}
			if tc.attached {
				decoder.streams = map[uint64]*middleStream{streamID: {}}
			}
			var reservations int
			budget := &bufferBudget{shared: func(delta int) bool {
				if delta > 0 {
					reservations++
				}
				return !tc.refuse
			}}
			_, _, err := decoder.readFrame(budget, maxRPCPacket)
			if err != errRPCFrame || decoder.readSeq != 0 || budget.used.Load() != 0 {
				t.Fatalf("unexpected result at prefix: error=%v sequence=%d charge=%d",
					err, decoder.readSeq, budget.used.Load())
			}
			if !tc.refuse && reservations != 0 {
				t.Fatalf("sequence validation reserved %d payload buffers", reservations)
			}
		})
	}
}

func TestLargeBackendBufferReusePreservesAdmission(t *testing.T) {
	const size = maxPooledBufferSize + 4
	allow := true
	budget := &bufferBudget{shared: func(delta int) bool { return delta <= 0 || allow }}
	first, err := borrowBuffer(size, budget)
	if err != nil {
		t.Fatal(err)
	}
	address := &first.data[0]
	first.data[0], first.data[size-1] = 17, 31
	first.data = first.data[:size-4]
	first.release()

	different, err := borrowBuffer(size+4, budget)
	if err != nil {
		t.Fatal(err)
	}
	defer different.release()
	if &different.data[0] == address || cap(different.data) != size+4 {
		t.Fatal("a different capacity reused the released storage")
	}
	allow = false
	if denied, err := borrowBuffer(size, budget); err != errBufferBudget {
		denied.release()
		t.Fatalf("borrowing without budget returned %v", err)
	}
	if got := budget.used.Load(); got != size+4 {
		t.Fatalf("denied borrow left %d bytes charged", got)
	}
	allow = true
	reused, err := borrowBuffer(size, budget)
	if err != nil {
		t.Fatal(err)
	}
	defer reused.release()
	if &reused.data[0] != address || cap(reused.data) != size || budget.used.Load() != 2*size+4 {
		t.Fatal("the cache changed the allocation size or live charge")
	}
	if !bytes.Equal(reused.data, make([]byte, size)) {
		t.Fatal("the cache retained bytes from a previous borrower")
	}
}

func TestRPCTruncatedLargeAnswerReleasesBorrowedBuffer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const streamID, size = 11, 512 << 10
		conn, peer := net.Pipe()
		defer conn.Close()
		defer peer.Close()
		decoder := &middleConn{reader: conn, streams: map[uint64]*middleStream{streamID: {}}}
		budget := &bufferBudget{}
		seed, err := borrowBuffer(size, budget)
		if err != nil {
			t.Fatal(err)
		}
		address := &seed.data[0]
		seed.release()
		result := make(chan error, 1)
		go func() {
			_, _, err := decoder.readFrame(budget, maxRPCPacket)
			result <- err
		}()
		var partial [rpcFrameHeader + rpcProxyAnswerHeader + 4]byte
		le.PutUint32(partial[:], size)
		le.PutUint32(partial[rpcFrameHeader:], rpcProxyAns)
		le.PutUint64(partial[rpcFrameHeader+8:], streamID)
		if _, err := peer.Write(partial[:]); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if used := budget.used.Load(); used != size {
			t.Fatalf("incomplete answer reserved %d bytes, want %d", used, size)
		}
		_ = peer.Close()
		if err := <-result; err != io.ErrUnexpectedEOF {
			t.Fatalf("incomplete answer returned %v", err)
		}
		if used := budget.used.Load(); used != 0 || decoder.readSeq != 0 {
			t.Fatalf("incomplete answer reserved %d bytes or advanced sequence to %d", used, decoder.readSeq)
		}
		next, err := borrowBuffer(size, budget)
		if err != nil {
			t.Fatal(err)
		}
		defer next.release()
		if &next.data[0] == address {
			t.Fatal("truncated answer returned its large buffer to the cache")
		}
	})
}

func TestRPCLargeLateAnswerUsesNoPayloadBudget(t *testing.T) {
	const closedID, liveID = 11, 22
	payload := bytes.Repeat([]byte{19}, 512<<10)
	for _, tc := range []struct {
		name   string
		seq    int32
		change func([]byte) []byte
		err    error
	}{
		{name: "valid"},
		{name: "sequence", seq: 1, err: errRPCFrame},
		{name: "checksum", err: errRPCFrame, change: func(wire []byte) []byte {
			wire[len(wire)-1] ^= 1
			return wire
		}},
		{name: "truncated", err: io.ErrUnexpectedEOF, change: func(wire []byte) []byte { return wire[:len(wire)-1] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, peer := net.Pipe()
			defer peer.Close()
			encoder := middleConn{writeSeq: tc.seq}
			var answer [rpcProxyAnswerHeader]byte
			le.PutUint32(answer[:], rpcProxyAns)
			le.PutUint64(answer[8:], closedID)
			wire := encoder.appendFrame(nil, rpcFrameSize(answer[:], payload), answer[:], payload)
			if tc.change != nil {
				wire = tc.change(wire)
			} else if tc.err == nil {
				le.PutUint64(answer[8:], liveID)
				wire = encoder.appendFrame(wire, rpcFrameSize(answer[:], payload), answer[:], payload)
			}
			var reservations []int
			budget := &bufferBudget{shared: func(delta int) bool {
				if delta > 0 {
					reservations = append(reservations, delta)
				}
				return true
			}}
			middle := &middleConn{
				conn: conn, reader: bytes.NewReader(wire), budget: budget, stats: &backendStats{},
				streams: make(map[uint64]*middleStream), done: make(chan struct{}), writes: make(chan *middleWrite, middleWriteQueue),
			}
			defer middle.close()
			live := middle.attach(liveID, conn)
			defer live.finish(false)
			err := middle.readStreams()
			if tc.err != nil {
				if err != tc.err || middle.readSeq != 0 || len(reservations) != 0 || len(middle.writes) != 0 {
					t.Fatalf("invalid discarded frame advanced the connection: err=%v seq=%d reservations=%v controls=%d", err, middle.readSeq, reservations, len(middle.writes))
				}
				return
			}
			if err != io.EOF || middle.readSeq != 2 || len(reservations) != 1 || reservations[0] != rpcFrameSize(answer[:], payload) {
				t.Fatalf("unexpected read result %v, sequence %d or allocations %v", err, middle.readSeq, reservations)
			}
			select {
			case packet := <-live.packets:
				ok := bytes.Equal(packet.frame.data[8+rpcProxyAnswerHeader:], payload)
				live.release(packet)
				if !ok || budget.used.Load() != 0 {
					t.Fatal("live frame changed or its budget was retained")
				}
			default:
				t.Fatal("live response was not delivered")
			}
			select {
			case request := <-middle.writes:
				if le.Uint32(request.prefix) != rpcCloseConn || le.Uint64(request.prefix[4:]) != closedID {
					t.Fatal("unexpected control frame for the late response")
				}
			default:
				t.Fatal("missing close for the late response")
			}
		})
	}
}

func TestRPCBufferPressurePreservesControlAndUnrelatedStream(t *testing.T) {
	const liveID, droppedID = 11, 22
	const token = 0x10203040
	var encoder middleConn
	var ack [rpcSimpleAckBody]byte
	le.PutUint32(ack[:], rpcSimpleAck)
	le.PutUint64(ack[4:], liveID)
	le.PutUint32(ack[12:], token)
	var answer [rpcProxyAnswerHeader]byte
	le.PutUint32(answer[:], rpcProxyAns)
	le.PutUint64(answer[8:], liveID)
	wire := encoder.appendFrame(nil, rpcFrameSize(ack[:], answer[:]), ack[:], answer[:])
	wire = encoder.appendFrame(wire, rpcFrameSize(answer[:]), answer[:])
	wire = encoder.appendFrame(wire, rpcFrameSize(ack[:]), ack[:])
	le.PutUint64(answer[8:], droppedID)
	large := make([]byte, 512<<10)
	wire = encoder.appendFrame(wire, rpcFrameSize(answer[:], large), answer[:], large)
	le.PutUint64(answer[8:], liveID)
	payload := []byte{1, 2, 3, 4}
	wire = encoder.appendFrame(wire, rpcFrameSize(answer[:], payload), answer[:], payload)

	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	otherConn, otherPeer := net.Pipe()
	defer otherConn.Close()
	defer otherPeer.Close()
	decoder := &middleConn{
		conn: conn, reader: bytes.NewReader(wire), stats: &backendStats{},
		streams: make(map[uint64]*middleStream),
	}
	decoder.budget = &bufferBudget{shared: func(delta int) bool {
		return delta <= 0 || decoder.readSeq == 4
	}}
	live := decoder.attach(liveID, conn)
	other := decoder.attach(droppedID, otherConn)
	defer live.finish(false)
	defer other.finish(false)
	if err := decoder.readStreams(); err != io.EOF {
		t.Fatalf("read RPC stream: %v", err)
	}
	if active, _ := decoder.load(); active != 1 || decoder.stats.slowStreams.Load() != 1 || decoder.readSeq != 5 {
		t.Fatalf("unexpected stream state: active=%d, dropped=%d, sequence=%d", active, decoder.stats.slowStreams.Load(), decoder.readSeq)
	}
	if len(live.packets) != 2 {
		t.Fatalf("expected ACK and data, got %d packets", len(live.packets))
	}
	gotAck := <-live.packets
	live.release(gotAck)
	if gotAck.frame.data != nil || gotAck.ack != token {
		t.Fatalf("unexpected ACK: frame=%t, token=%08x", gotAck.frame.data != nil, gotAck.ack)
	}
	gotData := <-live.packets
	data := gotData.frame.data
	dataOK := len(data) == 8+rpcProxyAnswerHeader+len(payload) && bytes.Equal(data[8+rpcProxyAnswerHeader:], payload)
	live.release(gotData)
	if !dataOK || live.pending.Load() != 0 || decoder.budget.used.Load() != 0 {
		t.Fatalf("unexpected data or retained budget: data valid=%t, pending=%d, budget=%d", dataOK, live.pending.Load(), decoder.budget.used.Load())
	}
}

func TestRPCSlowStreamReleasesOnlyQueuedPackets(t *testing.T) {
	const slowID, liveID = 11, 22
	for _, tc := range []struct {
		name       string
		queued     int
		packetSize int
		answerSize int
		denyAnswer bool
	}{
		{name: "byte-limit", queued: 2, packetSize: 1 << 20, answerSize: 1 << 20},
		{name: "packet-limit", queued: maxMiddleStreamPackets, packetSize: 256, answerSize: 512 << 10},
		{name: "shared-budget", queued: 2, packetSize: 4096, answerSize: 64 << 10, denyAnswer: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, peer := net.Pipe()
			defer peer.Close()
			slow, slowPeer := net.Pipe()
			defer slowPeer.Close()
			defer slow.Close()
			decoder := &middleConn{
				conn: conn, writes: make(chan *middleWrite, middleWriteQueue), done: make(chan struct{}),
				streams: make(map[uint64]*middleStream), stats: &backendStats{}, budget: &bufferBudget{},
			}
			defer decoder.close()
			stalled := decoder.attach(slowID, slow)
			live := decoder.attach(liveID, conn)
			defer stalled.finish(false)
			defer live.finish(false)
			queueSlow := func() {
				packet, err := borrowBuffer(tc.packetSize, decoder.budget)
				if err != nil {
					t.Fatal(err)
				}
				decoder.dispatch(slowID, middlePacket{frame: packet})
			}
			queueSlow()
			// A client writer has already borrowed this packet and is stalled.
			inFlight := <-stalled.packets
			defer func() { stalled.release(inFlight) }()
			for range tc.queued {
				queueSlow()
			}
			cost := int64(cap(inFlight.frame.data))
			if used := decoder.budget.used.Load(); used != cost*int64(tc.queued+1) {
				t.Fatalf("fixture queued %d bytes, want %d", used, cost*int64(tc.queued+1))
			}
			var attemptedSlow, attemptedLive int
			decoder.budget.shared = func(delta int) bool {
				if delta <= 0 {
					return true
				}
				if decoder.readSeq == 0 {
					attemptedSlow++
					return !tc.denyAnswer
				}
				attemptedLive++
				return decoder.budget.used.Load() <= cost+int64(delta)
			}
			var encoder middleConn
			var answer [rpcProxyAnswerHeader]byte
			le.PutUint32(answer[:], rpcProxyAns)
			le.PutUint64(answer[8:], slowID)
			payload := make([]byte, tc.answerSize)
			wire := encoder.appendFrame(nil, rpcFrameSize(answer[:], payload), answer[:], payload)
			le.PutUint64(answer[8:], liveID)
			payload = []byte{1, 2, 3, 4}
			wire = encoder.appendFrame(wire, rpcFrameSize(answer[:], payload), answer[:], payload)
			decoder.reader = bytes.NewReader(wire)
			if err := decoder.readStreams(); err != io.EOF || decoder.readSeq != 2 {
				t.Fatalf("reading replies: %v, sequence %d", err, decoder.readSeq)
			}
			if active, ready := decoder.load(); !ready || active != 1 || decoder.stats.slowStreams.Load() != 1 {
				t.Fatalf("slow stream affected other streams: active=%d, ready=%t, slow=%d", active, ready, decoder.stats.slowStreams.Load())
			}
			if pending := stalled.pending.Load(); pending != cost {
				t.Errorf("slow stream retained %d bytes, want %d still owned by client writer", pending, cost)
			}
			if attemptedSlow != 1 || attemptedLive != 1 {
				t.Errorf("unexpected reservations: slow=%d, live=%d", attemptedSlow, attemptedLive)
			}
			select {
			case packet, ok := <-live.packets:
				data := packet.frame.data
				matches := ok && len(data) == 8+rpcProxyAnswerHeader+len(payload) && bytes.Equal(data[8+rpcProxyAnswerHeader:], payload)
				live.release(packet)
				if !matches {
					t.Fatal("live stream received a different response")
				}
			default:
				t.Fatal("slow stream starved the live one")
			}
			if decoder.budget.used.Load() != cost {
				t.Fatal("queued packet release affected the outstanding writer or leaked budget")
			}
			stalled.release(inFlight)
			inFlight = middlePacket{}
			if stalled.pending.Load() != 0 || decoder.budget.used.Load() != 0 {
				t.Fatal("writer did not release the last packet")
			}
		})
	}
}

func TestRPCRepeatedLateAnswersShareOnePendingClose(t *testing.T) {
	const closedID, liveID, pingID = 11, 22, 33
	var encoder middleConn
	var answer [rpcProxyAnswerHeader]byte
	le.PutUint32(answer[:], rpcProxyAns)
	le.PutUint64(answer[8:], closedID)
	payload := []byte{1, 2, 3, 4}
	var wire []byte
	for range 2 * middleControlSlots {
		wire = encoder.appendFrame(wire, rpcFrameSize(answer[:], payload), answer[:], payload)
	}
	var ping [rpcControlBody]byte
	le.PutUint32(ping[:], rpcPing)
	le.PutUint64(ping[4:], pingID)
	wire = encoder.appendFrame(wire, rpcFrameSize(ping[:]), ping[:])
	le.PutUint64(answer[8:], liveID)
	wire = encoder.appendFrame(wire, rpcFrameSize(answer[:], payload), answer[:], payload)

	conn, peer := net.Pipe()
	defer peer.Close()
	middle := &middleConn{
		conn: conn, reader: bytes.NewReader(wire), budget: &bufferBudget{}, stats: &backendStats{},
		streams: make(map[uint64]*middleStream), done: make(chan struct{}), writes: make(chan *middleWrite, middleWriteQueue),
	}
	defer middle.close()
	live := middle.attach(liveID, conn)
	defer live.finish(false)
	const dataSlots = middleWriteQueue - middleControlSlots
	for range dataSlots {
		if err := middle.queueWrite(&middleWrite{body: payload, result: make(chan error, 1)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := middle.notifyClosed(closedID); err != nil {
		t.Fatal(err)
	}
	if err := middle.readStreams(); err != io.EOF {
		t.Fatalf("read RPC streams: %v", err)
	}
	if _, ready := middle.load(); !ready || middle.stats.controlOverflows.Load() != 0 {
		t.Fatal("late answers closed the shared connection")
	}
	if got := len(middle.writes); got != dataSlots+2 {
		t.Fatalf("expected one close and one pong, got %d control frames", got-dataSlots)
	}
	for range dataSlots {
		<-middle.writes
	}
	closeFrame, pong := <-middle.writes, <-middle.writes
	if le.Uint32(closeFrame.prefix) != rpcCloseConn || le.Uint64(closeFrame.prefix[4:]) != closedID ||
		le.Uint32(pong.prefix) != rpcPong || le.Uint64(pong.prefix[4:]) != pingID {
		t.Fatal("unexpected RPC control types or values")
	}
	select {
	case packet, ok := <-live.packets:
		matches := ok && bytes.Equal(packet.frame.data[8+rpcProxyAnswerHeader:], payload)
		live.release(packet)
		if !matches {
			t.Fatal("the live stream received the wrong payload")
		}
	default:
		t.Fatal("the live stream missed its reply")
	}
	if middle.budget.used.Load() != 0 {
		t.Fatal("the released frames are still charged to the budget")
	}
	_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	written := make(chan struct{})
	go func() {
		middle.writeQueued([]*middleWrite{closeFrame, pong}, 2*rpcFrameSize(ping[:]))
		close(written)
	}()
	if err := middle.notifyClosed(closedID); err != nil || len(middle.writes) != 0 {
		t.Fatalf("an in-flight close did not absorb a duplicate: %v", err)
	}
	decoder := &middleConn{reader: peer}
	for _, request := range []*middleWrite{closeFrame, pong} {
		if got, err := decoder.read(maxRPCPacket); err != nil || !bytes.Equal(got, request.prefix) {
			t.Fatalf("unexpected control on the wire: %x, error %v", got, err)
		}
	}
	<-written
	if err := middle.notifyClosed(closedID); err != nil || len(middle.writes) != 1 {
		t.Fatalf("a subsequent late reply could not queue a close: %v", err)
	}
}

func TestEmbeddedPipeBorrowsOnlyForReadyData(t *testing.T) {
	relay, proxy := newProxyPipe()
	defer relay.Close()
	defer proxy.Close()
	borrowed := make(chan int, 1)
	output := make(chan error, 1)
	go func() {
		_, err := relay.ReadWithBuffer(4096, func(size int) ([]byte, error) {
			borrowed <- size
			return make([]byte, size), nil
		})
		output <- err
	}()
	select {
	case size := <-borrowed:
		t.Fatalf("idle connection borrowed %d bytes", size)
	case <-time.After(10 * time.Millisecond):
	}
	if _, err := proxy.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if n := <-borrowed; n != len("payload") {
		t.Fatalf("read borrowed %d bytes", n)
	}
	if err := <-output; err != nil {
		t.Fatal(err)
	}
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.ReadWithBuffer(4096, nil); err != io.EOF {
		t.Fatalf("closed connection read returned %v", err)
	}
}

func TestMiddlePoolGrowthUsesReadyConnection(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	address := listener.Addr().(*net.TCPAddr).AddrPort()
	routes := &routingConfig{dcs: map[int16][]netip.AddrPort{2: {address}}}
	warm := &middleConn{streams: make(map[uint64]*middleStream)}
	for i := uint64(1); i <= streamsBeforeGrowth; i++ {
		warm.attach(i, nil)
	}
	ctx, cancel := context.WithCancel(t.Context())
	b := &backend{
		ctx: ctx, cancel: cancel, log: zap.NewNop(),
		pools: map[middleTarget]*middlePool{{address: address}: {connections: []*middleConn{warm}}},
	}
	defer b.close()
	b.streamID.Store(streamsBeforeGrowth)
	b.routes.Store(routes)
	acquire, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	stream, err := b.acquireMiddle(acquire, 2, nil)
	if err != nil || stream.middle != warm {
		t.Fatalf("expansion did not use the ready connection: %v", err)
	}
	if err := listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	dial, err := listener.AcceptTCP()
	if err != nil {
		t.Fatalf("background expansion did not start: %v", err)
	}
	defer dial.Close()
}

func TestRouteRotationDrainsStreamsAndCancelsObsoleteDial(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	address := listener.Addr().(*net.TCPAddr).AddrPort()
	old := &routingConfig{dcs: map[int16][]netip.AddrPort{2: {address}}}
	next := &routingConfig{dcs: old.dcs, secret: [128]byte{9}}
	oldTarget := middleTarget{address: address, secret: old.secret}
	newTarget := middleTarget{address: address, secret: next.secret}
	newConnection := func() *middleConn {
		conn, peer := net.Pipe()
		t.Cleanup(func() { _ = peer.Close() })
		middle := &middleConn{conn: conn, done: make(chan struct{}), writes: make(chan *middleWrite, 1), streams: make(map[uint64]*middleStream)}
		t.Cleanup(middle.close)
		return middle
	}
	active, idle := newConnection(), newConnection()
	ctx, cancel := context.WithCancel(t.Context())
	b := &backend{ctx: ctx, cancel: cancel, log: zap.NewNop(), maxDials: 1}
	t.Cleanup(b.close)
	b.publishRoutes(old)
	b.pools = map[middleTarget]*middlePool{oldTarget: {connections: []*middleConn{active, idle}}}
	acquire, stop := context.WithTimeout(ctx, 4*time.Second)
	defer stop()
	stream, err := b.acquireMiddle(acquire, 2, nil)
	if err != nil || stream.middle != active {
		t.Fatalf("could not attach the original stream: %v", err)
	}
	original := stream
	defer original.finish(false)
	other := active.attach(b.streamID.Add(1), nil)
	if other == nil {
		t.Fatal("could not attach another stream to the original connection")
	}
	defer other.finish(false)
	b.poolMu.Lock()
	b.scheduleMiddle(oldTarget)
	notified := b.poolSignal()
	b.poolMu.Unlock()
	if err := listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	dial, err := listener.AcceptTCP()
	if err != nil {
		t.Fatalf("obsolete dial did not start: %v", err)
	}
	defer dial.Close()
	b.publishRoutes(next)
	select {
	case <-notified:
	default:
		t.Fatal("route update did not wake waiting streams")
	}
	if err := dial.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, dial); err != nil {
		t.Fatalf("obsolete handshake was not canceled: %v", err)
	}
	select {
	case <-idle.done:
	default:
		t.Fatal("obsolete idle connection stayed open")
	}
	if load, ready := active.load(); load != 2 || ready {
		t.Fatalf("old connection has %d streams and ready=%t", load, ready)
	}
	original.finish(true)
	select {
	case <-active.done:
		t.Fatal("retiring connection closed with a stream still attached")
	default:
	}
	select {
	case control := <-active.writes:
		if le.Uint32(control.prefix) != rpcCloseConn || le.Uint64(control.prefix[4:]) != original.id {
			t.Fatal("closing the first stream queued an unexpected RPC message")
		}
	default:
		t.Fatal("closing the first stream did not notify the peer")
	}
	payload := []byte{4, 5, 6}
	active.dispatch(other.id, middlePacket{frame: ownedBuffer{data: payload}})
	select {
	case packet := <-other.packets:
		if !bytes.Equal(packet.frame.data, payload) {
			t.Fatal("original stream lost data after rotation")
		}
		other.release(packet)
	default:
		t.Fatal("original stream stopped receiving after rotation")
	}
	current := newConnection()
	b.poolMu.Lock()
	b.pools[newTarget] = &middlePool{connections: []*middleConn{current}}
	b.poolMu.Unlock()
	stream, err = b.acquireMiddle(acquire, 2, nil)
	if err != nil || stream.middle != current {
		t.Fatalf("could not attach a stream to the new key: %v", err)
	}
	var remoteClose [rpcControlBody]byte
	le.PutUint32(remoteClose[:], rpcCloseExt)
	le.PutUint64(remoteClose[4:], other.id)
	active.handleControl(remoteClose[:])
	select {
	case <-active.done:
	default:
		t.Fatal("obsolete connection stayed open after the final stream detached")
	}
	if _, ready := current.load(); !ready {
		t.Fatal("closing the obsolete connection affected the new route")
	}
	stream.finish(false)
}

func TestReturningMiddleRouteStartsWithFreshPool(t *testing.T) {
	address := netip.MustParseAddrPort("127.0.0.1:10001")
	other := netip.MustParseAddrPort("127.0.0.1:10002")
	original := &routingConfig{dcs: map[int16][]netip.AddrPort{2: {address}}}
	replacement := &routingConfig{dcs: map[int16][]netip.AddrPort{2: {other}}}
	target := middleTarget{address: address}
	old := &middlePool{retryAfter: time.Now().Add(time.Minute)}
	b := &backend{pools: map[middleTarget]*middlePool{target: old}}
	b.publishRoutes(original)
	b.publishRoutes(replacement)
	b.publishRoutes(original)
	_, _, candidate, _ := b.chooseMiddle(original.secret, original.targets(2), 0, time.Now())
	if candidate != target {
		t.Fatal("returning route inherited the removed pool's retry deadline")
	}
}

func TestMiddlePoolWakesAtEarliestBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		slow := netip.MustParseAddrPort("127.0.0.1:10001")
		fast := netip.MustParseAddrPort("127.0.0.1:10002")
		now := time.Now()
		want := now.Add(375 * time.Millisecond)
		type attempt struct {
			address string
			at      time.Time
		}
		attempts := make(chan attempt, 2)
		ctx, cancel := context.WithCancel(t.Context())
		b := &backend{
			ctx: ctx, cancel: cancel, log: zap.NewNop(),
			pools: map[middleTarget]*middlePool{
				{address: slow}: {retryAfter: now.Add(time.Second)},
				{address: fast}: {retryAfter: want},
			},
			dialer: net.Dialer{Control: func(_, address string, _ syscall.RawConn) error {
				attempts <- attempt{address, time.Now()}
				return net.ErrClosed
			}},
		}
		defer b.close()
		b.publishRoutes(&routingConfig{dcs: map[int16][]netip.AddrPort{2: {slow, fast}}})
		deadline, stop := context.WithTimeout(ctx, 450*time.Millisecond)
		defer stop()
		result := make(chan error, 1)
		go func() {
			_, err := b.acquireMiddle(deadline, 2, nil)
			result <- err
		}()
		select {
		case got := <-attempts:
			if got.address != fast.String() || !got.at.Equal(want) {
				t.Fatalf("dial attempted at %v for %s, want %v for %s", got.at, got.address, want, fast)
			}
		case err := <-result:
			t.Fatalf("acquisition ended before attempting the eligible dial: %v", err)
		}
		stop()
		if err := <-result; err != context.Canceled {
			t.Fatalf("canceled acquisition returned %v", err)
		}
	})
}

func TestMiddlePoolWakesWhenDialSlotIsReleased(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := netip.MustParseAddrPort("127.0.0.1:10001")
		next := netip.MustParseAddrPort("127.0.0.1:10002")
		attempts := make(chan string, 2)
		release := make(chan struct{})
		ctx, cancel := context.WithCancel(t.Context())
		b := &backend{
			ctx: ctx, cancel: cancel, log: zap.NewNop(), maxDials: 1,
			dialer: net.Dialer{ControlContext: func(dial context.Context, _, address string, _ syscall.RawConn) error {
				attempts <- address
				if address == first.String() {
					select {
					case <-release:
					case <-dial.Done():
					}
				}
				return net.ErrClosed
			}},
		}
		defer b.close()
		b.publishRoutes(&routingConfig{dcs: map[int16][]netip.AddrPort{2: {first}, 4: {next}}})
		wait, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		go func() { _, _ = b.acquireMiddle(wait, 2, nil) }()
		select {
		case address := <-attempts:
			if address != first.String() {
				t.Fatalf("first dial went to %s, want %s", address, first)
			}
		case <-wait.Done():
			t.Fatal("first dial did not start")
		}
		go func() { _, _ = b.acquireMiddle(wait, 4, nil) }()
		synctest.Wait()
		if len(attempts) != 0 {
			t.Fatal("second dial exceeded the concurrent dial limit")
		}
		releasedAt := time.Now()
		close(release)
		select {
		case address := <-attempts:
			if address != next.String() || !time.Now().Equal(releasedAt) {
				t.Fatalf("dial to %s did not start immediately after releasing the slot", address)
			}
		case <-wait.Done():
			t.Fatal("waiting stream did not observe the released dial slot")
		}
	})
}

type failedMiddleWriter struct{ net.Conn }

func (c failedMiddleWriter) Read(dst []byte) (int, error) {
	n, err := c.Conn.Read(dst)
	if err == io.ErrClosedPipe {
		err = net.ErrClosed
	}
	return n, err
}

func (failedMiddleWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestMiddleWriteFailureBacksOffPool(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	b := &backend{ctx: ctx, log: zap.NewNop(), sockets: 1}
	conn, peer := net.Pipe()
	defer peer.Close()
	transport := failedMiddleWriter{conn}
	middle := &middleConn{
		conn: transport, reader: transport, stats: &b.stats,
		done: make(chan struct{}), writes: make(chan *middleWrite, middleWriteQueue),
	}
	pool := &middlePool{connections: []*middleConn{middle}}
	if err := middle.sendControl(rpcPing, 1); err != nil {
		t.Fatal(err)
	}
	b.runMiddle(pool, middle)
	if b.stats.writeFailures.Load() != 1 || b.stats.disconnects.Load() != 1 || !pool.retryAfter.After(time.Now()) {
		t.Fatalf("write failures=%d, disconnects=%d, backoff=%v", b.stats.writeFailures.Load(), b.stats.disconnects.Load(), pool.retryAfter)
	}
}
