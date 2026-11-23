package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/love4taylor/caddy-tproxy/internal/config"
	"github.com/love4taylor/caddy-tproxy/internal/frame"
	"github.com/love4taylor/caddy-tproxy/internal/session"
)

const (
	webSocketProtocolPrefix     = "tproxy-v1."
	webSocketLaneProtocolPrefix = "tproxy-lane-v1."
	binaryBody                  = "application/octet-stream"
	carrierWriteTimeout         = 30 * time.Second
	maxCreateBodyBytes          = 64
)

var (
	wsBuffers      sync.Pool
	strictToken    = base64.RawURLEncoding.Strict()
	errCarrierBody = errors.New("invalid carrier body")
)

func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request, route string) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery || duplicateTransportHeaders(r.Header) || headerHasValue(r.Header, "Content-Encoding") {
		http.NotFound(w, r)
		return
	}
	address, err := s.clientIP(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if route == "api/v1/ws" {
		s.serveWebSocket(w, r)
		return
	}
	token, auth := bearerToken(r.Header.Get("Authorization"))
	if !auth || headerHasValue(r.Header, "Cookie") {
		http.NotFound(w, r)
		return
	}
	switch route {
	case "api/v1/session":
		s.serveSession(w, r, token, address)
	case "api/v1/up", "api/v1/down":
		s.serveHTTPBatch(w, r, token, route == "api/v1/up")
	default:
		http.NotFound(w, r)
	}
}

func headerHasValue(headers http.Header, name string) bool {
	for _, value := range headers.Values(name) {
		if value != "" {
			return true
		}
	}
	return false
}

func duplicateTransportHeaders(h http.Header) bool {
	for _, field := range [...]string{"Authorization", "Sec-Websocket-Protocol", "Content-Type", "X-Up-Seq", "X-Down-Cursor", "X-Lane-Id"} {
		if len(h[field]) > 1 {
			return true
		}
	}
	return false
}

func (s *Server) serveSession(w http.ResponseWriter, r *http.Request, token, address string) {
	if r.Method == http.MethodDelete {
		if r.Header.Get("Content-Type") == "" && emptyBody(r) && s.manager.CloseToken(token) == nil {
			w.WriteHeader(http.StatusNoContent)
		} else {
			http.NotFound(w, r)
		}
		return
	}
	if r.Method != http.MethodPost || !binaryContentType(r.Header.Get("Content-Type")) ||
		!s.manager.HasBootstrap(token) || r.Body == nil || r.ContentLength > maxCreateBodyBytes {
		http.NotFound(w, r)
		return
	}
	body := http.MaxBytesReader(w, r.Body, maxCreateBodyBytes)
	defer body.Close()
	var hello [9]byte
	if _, err := io.ReadFull(body, hello[:]); err != nil || !readerEOF(body) {
		http.NotFound(w, r)
		return
	}
	created, err := s.manager.Create(token, address, hello[:])
	if err != nil {
		s.carrierError(w, r, err)
		return
	}
	w.Header().Set("X-Session-Token", created.Token)
	w.Header().Set("X-Carrier-Mode", string(created.Session.CarrierMode()))
	w.Header().Set("X-Down-Cursor", "0")
	writeBinary(w, created.Welcome)
}

func (s *Server) carrierError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, session.ErrLimit), errors.Is(err, session.ErrBackpressure), errors.Is(err, session.ErrConcurrent):
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
	case r.Context().Err() == nil:
		http.NotFound(w, r)
	}
}

func parseHTTPLane(mode config.CarrierMode, field string) (id uint32, valid bool) {
	switch mode {
	case config.CarrierHTTPS:
		return 0, field == ""
	case config.CarrierHTTPSLanes:
		n, ok := canonicalUint(field)
		return uint32(n), ok && n <= frame.MaxStreamID
	}
	return 0, false
}

func (s *Server) serveHTTPBatch(w http.ResponseWriter, r *http.Request, token string, upload bool) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	active, err := s.manager.Get(token)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	lane, valid := parseHTTPLane(active.CarrierMode(), r.Header.Get("X-Lane-ID"))
	if !valid {
		http.NotFound(w, r)
		return
	}
	if upload {
		s.acceptBatch(w, r, active, lane)
		return
	}
	cursor, ok := canonicalUint(r.Header.Get("X-Down-Cursor"))
	if !ok || r.Header.Get("Content-Type") != "" || !emptyBody(r) {
		http.NotFound(w, r)
		return
	}
	batch, next, closed, err := pollCarrier(r.Context(), active, lane, cursor)
	if err != nil {
		s.carrierError(w, r, err)
		return
	}
	if batch != nil {
		defer batch.Release()
	}
	w.Header().Set("X-Down-Cursor", strconv.FormatUint(next, 10))
	if closed {
		w.Header().Set("X-Lane-Closed", "1")
	}
	if batch == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	controller := http.NewResponseController(w)
	listener, _ := r.Context().Value(http.ServerContextKey).(*http.Server)
	if listener == nil || listener.WriteTimeout <= 0 {
		if controller.SetWriteDeadline(time.Now().Add(carrierWriteTimeout)) != nil {
			w.Header().Del("X-Down-Cursor")
			w.Header().Del("X-Lane-Closed")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}
	defer interruptDownlinkOnClose(r, controller, active).finish()
	writeBinaryHeader(w, batch.Len())
	if _, err := batch.WriteTo(w); err == nil {
		_ = controller.Flush()
	}
}

func (s *Server) acceptBatch(w http.ResponseWriter, r *http.Request, active *session.Session, lane uint32) {
	sequence, valid := canonicalUint(r.Header.Get("X-Up-Seq"))
	if !valid || sequence == 0 || r.Body == nil || !binaryContentType(r.Header.Get("Content-Type")) {
		http.NotFound(w, r)
		return
	}
	upload, err := active.BeginHTTPUpload(lane, sequence)
	if err != nil {
		s.carrierError(w, r, err)
		return
	}
	defer upload.Release()
	reader := http.MaxBytesReader(w, r.Body, int64(s.config.Limits.MaxBodyBytes))
	var interrupted sync.WaitGroup
	interrupted.Add(1)
	stop := active.OnClose(func() {
		defer interrupted.Done()
		_ = http.NewResponseController(w).SetReadDeadline(time.Now())
	})
	body, err := s.readBatch(reader, r.ContentLength)
	if err != nil {
		s.carrierError(w, r, err)
	}
	// HTTP/1 may still read unread bytes while closing a rejected body.
	// Keep the session's read interrupt active until that drain finishes.
	_ = reader.Close()
	if !stop() {
		// The deadline belongs to this request, even if the listener reuses the connection.
		interrupted.Wait()
	}
	if err != nil {
		return
	}
	defer body.release()
	ack, err := upload.Submit(body.Bytes)
	if err != nil {
		s.carrierError(w, r, err)
		return
	}
	w.Header().Set("X-Up-Ack", strconv.FormatUint(ack, 10))
	w.WriteHeader(http.StatusNoContent)
}

func pollCarrier(ctx context.Context, active *session.Session, id uint32, cursor uint64) (*session.Downlink, uint64, bool, error) {
	if active.CarrierMode() == config.CarrierHTTPSLanes || active.CarrierMode() == config.CarrierWebSocketLanes {
		return active.PollLane(ctx, id, cursor)
	}
	batch, cursor, err := active.Poll(ctx, cursor)
	return batch, cursor, false, err
}

func writeBinary(w http.ResponseWriter, data []byte) {
	writeBinaryHeader(w, len(data))
	_, _ = w.Write(data)
}

func writeBinaryHeader(w http.ResponseWriter, length int) {
	w.Header().Set("Content-Type", binaryBody)
	w.Header().Set("Content-Length", strconv.Itoa(length))
	w.WriteHeader(http.StatusOK)
}

type upgradeWriter struct {
	http.ResponseWriter
	active *session.Session
	stop   func() bool
}

func (w *upgradeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err == nil {
		// Once hijacked, the connection can block while writing the 101 response.
		w.stop = w.active.OnClose(func() { _ = conn.Close() })
	}
	return conn, rw, err
}

func (s *Server) serveWebSocket(w http.ResponseWriter, r *http.Request) {
	protocol, id, lanes, valid := webSocketCredentials(r.Header.Get("Sec-WebSocket-Protocol"))
	if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" || !valid || !tokenSyntax(protocol) || !emptyBody(r) {
		http.NotFound(w, r)
		return
	}
	active, err := s.manager.Get(protocol)
	if err != nil || (lanes && active.CarrierMode() != config.CarrierWebSocketLanes) ||
		(!lanes && active.CarrierMode() != config.CarrierWebSocket) {
		http.NotFound(w, r)
		return
	}
	if lanes {
		if !s.manager.ReserveWebSocketLane() {
			http.NotFound(w, r)
			return
		}
		defer s.manager.ReleaseWebSocketLane()
	}
	if !active.ClaimWebSocket(id) {
		http.NotFound(w, r)
		return
	}
	writer := upgradeWriter{ResponseWriter: w, active: active}
	established := false
	defer func() {
		if writer.stop != nil {
			writer.stop()
		}
		active.EndWebSocket(id, established)
	}()
	upgrader := websocket.Upgrader{
		HandshakeTimeout: carrierWriteTimeout,
		WriteBufferSize:  16 << 10, WriteBufferPool: &wsBuffers,
		Subprotocols: []string{r.Header.Get("Sec-WebSocket-Protocol")},
		CheckOrigin:  func(*http.Request) bool { return true },
	}
	socket, err := upgrader.Upgrade(&writer, r, nil)
	if err != nil {
		return
	}
	established = true
	defer socket.Close()
	socket.SetReadLimit(int64(s.config.Limits.MaxBodyBytes))
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		defer cancel()
		defer socket.Close()
		s.receiveSocket(ctx, socket, active, id)
	}()
	writeSocket(ctx, socket, active, id)
	cancel()
	_ = socket.Close()
	<-readDone
}

func (s *Server) receiveSocket(ctx context.Context, socket *websocket.Conn, active *session.Session, id uint32) {
	idle := 2 * s.config.Timeouts.LongPoll
	refresh := func() error { return socket.SetReadDeadline(time.Now().Add(idle)) }
	if refresh() != nil {
		return
	}
	socket.SetPongHandler(func(string) error { return refresh() })
	for sequence := uint64(1); sequence != 0; sequence++ {
		kind, reader, err := socket.NextReader()
		if err != nil || kind != websocket.BinaryMessage {
			return
		}
		batch, err := s.readBatch(reader, -1)
		if err != nil {
			return
		}
		if refresh() != nil {
			batch.release()
			return
		}
		ack, err := active.ProcessWebSocket(ctx, id, sequence, batch.Bytes)
		batch.release()
		if err != nil || ack != sequence {
			return
		}
	}
}

func writeSocket(ctx context.Context, socket *websocket.Conn, active *session.Session, id uint32) {
	var cursor uint64
	for {
		batch, next, closed, err := pollCarrier(ctx, active, id, cursor)
		deadline := time.Now().Add(carrierWriteTimeout)
		if batch == nil {
			if err != nil || closed || socket.WriteControl(websocket.PingMessage, nil, deadline) != nil {
				return
			}
			continue
		}
		if err == nil && !closed {
			err = socket.SetWriteDeadline(deadline)
			if err == nil {
				err = writeSocketBatch(socket, batch)
			}
		}
		batch.Release()
		if closed || err != nil {
			return
		}
		cursor = next
	}
}

func writeSocketBatch(socket *websocket.Conn, batch *session.Downlink) error {
	if body := batch.WebSocketMessage(); body != nil {
		return socket.WriteMessage(websocket.BinaryMessage, body)
	}
	writer, err := socket.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return err
	}
	if _, err := batch.WriteTo(writer); err != nil {
		return err
	}
	return writer.Close()
}

func webSocketCredentials(value string) (token string, id uint32, isLane, ok bool) {
	if rest, found := strings.CutPrefix(value, webSocketLaneProtocolPrefix); found {
		text, lane, found := strings.Cut(rest, ".")
		n, valid := canonicalUint(lane)
		if !found || text == "" || !valid || n == 0 || n > frame.MaxStreamID {
			return "", 0, false, false
		}
		return text, uint32(n), true, true
	}
	if rest, found := strings.CutPrefix(value, webSocketProtocolPrefix); found && rest != "" {
		return rest, 0, false, true
	}
	return "", 0, false, false
}

func bearerToken(value string) (string, bool) {
	token, found := strings.CutPrefix(value, "Bearer ")
	return token, found && tokenSyntax(token)
}

func tokenSyntax(token string) bool {
	if len(token) != 43 {
		return false
	}
	var decoded [32]byte
	n, err := strictToken.Decode(decoded[:], []byte(token))
	return err == nil && n == len(decoded)
}

func canonicalUint(value string) (uint64, bool) {
	if len(value) == 0 || len(value) > 20 || (len(value) > 1 && value[0] == '0') {
		return 0, false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(value, 10, 64)
	return n, err == nil
}

func binaryContentType(value string) bool {
	if value == binaryBody {
		return true
	}
	kind, params, err := mime.ParseMediaType(value)
	return err == nil && kind == binaryBody && len(params) == 0
}

func emptyBody(r *http.Request) bool {
	return r.ContentLength <= 0 && (r.Body == nil || r.Body == http.NoBody || readerEOF(r.Body))
}

func readerEOF(reader io.Reader) bool {
	var extra [1]byte
	n, err := reader.Read(extra[:])
	return n == 0 && err == io.EOF
}

type carrierBody struct {
	frame.BatchBuffer
	charge *session.Manager
}

func (body *carrierBody) acquire(size, limit int) bool {
	body.BatchBuffer = frame.BorrowBatchBuffer(size, limit, body.charge.ChangeBufferBudget)
	return body.Bytes != nil
}

func (body *carrierBody) release() {
	if body.Bytes == nil {
		return
	}
	size := cap(body.Bytes)
	body.Recycle()
	body.charge.ChangeBufferBudget(-size)
}

func (s *Server) readBatch(reader io.Reader, expected int64) (result carrierBody, err error) {
	limit := s.config.Limits.MaxBodyBytes
	if expected > int64(limit) || expected == 0 {
		return carrierBody{}, errCarrierBody
	}
	size := min(limit, frame.InitialBatchBufferBytes)
	if expected > 0 {
		size = int(expected)
	}
	body := carrierBody{charge: s.manager}
	if !body.acquire(size, limit) {
		return carrierBody{}, session.ErrBackpressure
	}
	defer func() {
		if err != nil {
			body.release()
		}
	}()
	used, readErr := fillCarrierBody(reader, body.Bytes)
	var byteAfter [1]byte
	for readErr == nil {
		// A full buffer alone does not prove that the transport ended the
		// body. Check for a clean EOF before accepting the batch.
		var n int
		n, readErr = fillCarrierBody(reader, byteAfter[:])
		if n == 0 || (readErr != nil && readErr != io.EOF) {
			break
		}
		if expected > 0 || used == limit {
			return carrierBody{}, errCarrierBody
		}
		grown := used + min(used, limit-used)
		next := carrierBody{charge: body.charge}
		if !next.acquire(grown, limit) {
			return carrierBody{}, session.ErrBackpressure
		}
		copy(next.Bytes, body.Bytes)
		body.release()
		body = next
		body.Bytes[used] = byteAfter[0]
		used++
		if readErr == nil {
			n, readErr = fillCarrierBody(reader, body.Bytes[used:])
			used += n
		}
	}
	if readErr != io.EOF || used == 0 {
		return carrierBody{}, readErr
	}
	if expected > 0 && int64(used) != expected {
		return carrierBody{}, io.ErrUnexpectedEOF
	}
	body.Bytes = body.Bytes[:used]
	return body, nil
}

// Preserve the transport's exact error, even when it arrives with the last
// bytes. io.ReadFull turns a clean short EOF into io.ErrUnexpectedEOF and
// suppresses an error when the destination fills.
func fillCarrierBody(reader io.Reader, dst []byte) (int, error) {
	used := 0
	for used < len(dst) {
		n, err := reader.Read(dst[used:])
		used += n
		if err != nil {
			return used, err
		}
	}
	return used, nil
}
