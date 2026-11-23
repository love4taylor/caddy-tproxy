package session

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"time"

	"github.com/love4taylor/caddy-tproxy/internal/config"
	"github.com/love4taylor/caddy-tproxy/internal/frame"
)

type upload struct {
	body      []byte
	digest    [sha256.Size]byte
	frames    frame.Batch
	err       error
	decoded   bool
	retryable bool
}

func (u *upload) decode(limit int, perLane bool, id uint32) {
	if u.decoded {
		return
	}
	u.decoded = true
	// The configured DATA limit can be smaller than a session PONG.
	u.err = u.frames.Decode(u.body, max(limit, frame.MaxPongPayload))
	if u.err != nil {
		return
	}
	for _, f := range u.frames.Frames() {
		if frame.ValidateClientShape(f) != nil || (perLane && f.StreamID != id) ||
			(f.Type == frame.Data && len(f.Payload) > limit) {
			u.err = ErrProtocol
			return
		}
	}
}

func mayIgnoreAfterClose(frames []frame.Frame) bool {
	return len(frames) > 0 && !slices.ContainsFunc(frames, func(f frame.Frame) bool {
		switch f.Type {
		case frame.Data, frame.Window, frame.Close:
			return false
		}
		return true
	})
}

// HTTPUpload reserves a reader through the lifetime of its request body.
type HTTPUpload struct {
	session  *Session
	id       uint32
	sequence uint64
	replay   bool
}

// BeginHTTPUpload reserves a reader before it allocates or reads a request
// body. Tentative lane IDs count against the same bound as opened streams.
func (s *Session) BeginHTTPUpload(id uint32, sequence uint64) (HTTPUpload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return HTTPUpload{}, ErrClosed
	}
	if id == 0 {
		if s.httpUploading {
			return HTTPUpload{}, ErrConcurrent
		}
		s.httpUploading = true
	} else {
		if _, active := s.httpLaneUploads[id]; active {
			return HTTPUpload{}, ErrConcurrent
		}
		if len(s.httpLaneUploads) >= s.limits.MaxStreamsPerSession {
			return HTTPUpload{}, ErrLimit
		}
		if s.httpLaneUploads == nil {
			s.httpLaneUploads = make(map[uint32]struct{})
		}
		s.httpLaneUploads[id] = struct{}{}
	}
	upload := HTTPUpload{session: s, id: id, sequence: sequence}
	if s.carrier == config.CarrierHTTPSLanes && sequence != 0 {
		lane := s.carrierLanes[id]
		upload.replay = lane != nil && lane.lastUpSequence == sequence
	}
	return upload, nil
}

// Release releases the reader after its body and buffer are released.
func (u HTTPUpload) Release() {
	s := u.session
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastActivity = time.Now()
	if u.id == 0 {
		s.httpUploading = false
	} else {
		delete(s.httpLaneUploads, u.id)
	}
}

// Submit accepts a complete body while the upload reservation is held.
func (u HTTPUpload) Submit(body []byte) (uint64, error) {
	s := u.session
	digest := sha256.Sum256(body)
	if u.replay {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return 0, ErrClosed
		}
		// A lane can be removed while the request body is being read.
		if lane := s.carrierLanes[u.id]; lane != nil && lane.lastUpSequence == u.sequence {
			s.lastActivity = time.Now()
			return s.replayUploadLocked(u.id, u.sequence, lane.lastUpDigest, digest)
		}
		s.mu.Unlock()
	}
	return s.acceptUpload(u.id, u.sequence, &upload{body: body, digest: digest, retryable: true})
}

func (s *Session) ProcessUp(sequence uint64, body []byte) (uint64, error) {
	if s.usesCarrierLanes() {
		return 0, ErrProtocol
	}
	return s.acceptUpload(0, sequence, &upload{body: body, digest: sha256.Sum256(body), retryable: true})
}

func (s *Session) ProcessUpLane(id uint32, sequence uint64, body []byte) (uint64, error) {
	if !s.usesCarrierLanes() || id > frame.MaxStreamID {
		return 0, ErrProtocol
	}
	return s.acceptUpload(id, sequence, &upload{body: body, digest: sha256.Sum256(body), retryable: true})
}

func (s *Session) ProcessWebSocket(ctx context.Context, id uint32, sequence uint64, body []byte) (uint64, error) {
	if id > frame.MaxStreamID {
		return 0, ErrProtocol
	}
	// The socket reader supplies a fresh sequence for every ordered message.
	// Only HTTP retries need a digest of an already committed body.
	in := upload{body: body}
	ack, err := s.acceptUpload(id, sequence, &in)
	if !errors.Is(err, ErrBackpressure) {
		return ack, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		s.mu.Lock()
		local := s.budgetSignalLocked()
		s.mu.Unlock()
		var global <-chan struct{}
		if s.manager != nil {
			global = s.manager.budgetSignal()
		}
		ack, err := s.acceptUpload(id, sequence, &in)
		if !errors.Is(err, ErrBackpressure) {
			return ack, err
		}
		select {
		case <-local:
		case <-global:
		case <-s.lifetime.Done():
			return 0, ErrClosed
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				return 0, ErrBackpressure
			}
			return 0, ctx.Err()
		}
	}
}

func (s *Session) acceptUpload(id uint32, sequence uint64, in *upload) (uint64, error) {
	perLane := s.usesCarrierLanes()
	if perLane {
		// Do the wire validation outside the session lock, without publishing a
		// lane for a request that has yet to pass admission.
		in.decode(s.limits.MaxFramePayload, true, id)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, ErrClosed
	}
	s.lastActivity = time.Now()
	last, digest := &s.lastUpSequence, &s.lastUpDigest
	var lane *carrierLane
	if perLane {
		lane = s.carrierLanes[id]
		if in.err != nil {
			return s.rejectUploadLocked(id)
		}
		if lane != nil {
			last, digest = &lane.lastUpSequence, &lane.lastUpDigest
		} else {
			frames := in.frames.Frames()
			if id != 0 && mayIgnoreAfterClose(frames) {
				s.mu.Unlock()
				return sequence, nil
			}
			if id == 0 || len(frames) == 0 || frames[0].Type != frame.Open {
				return s.rejectUploadLocked(id)
			}
			last, digest = nil, nil
		}
	}
	next := uint64(1)
	if last != nil {
		next = *last + 1
		if in.retryable && sequence != 0 && sequence == *last {
			return s.replayUploadLocked(id, sequence, *digest, in.digest)
		}
	}
	if sequence == 0 || sequence != next {
		return s.rejectUploadLocked(id)
	}
	if !perLane && !in.decoded {
		if s.upActive {
			s.mu.Unlock()
			return 0, ErrConcurrent
		}
		s.upActive = true
		s.mu.Unlock()
		in.decode(s.limits.MaxFramePayload, false, 0)
		s.mu.Lock()
		s.upActive = false
		if s.closed {
			s.mu.Unlock()
			return 0, ErrClosed
		}
	} else if !perLane && s.upActive {
		s.mu.Unlock()
		return 0, ErrConcurrent
	}
	if in.err != nil {
		return s.rejectUploadLocked(id)
	}
	frames := in.frames.Frames()
	cost, items, valid := s.planUplinkLocked(frames)
	if !valid {
		return s.rejectUploadLocked(id)
	}
	if cost != 0 && !s.reservePendingLocked(cost, items, pendingUplink) {
		s.mu.Unlock()
		return 0, ErrBackpressure
	}
	if perLane && lane == nil {
		lane = newCarrierLane()
		s.carrierLanes[id] = lane
		last, digest = &lane.lastUpSequence, &lane.lastUpDigest
	}
	start, stop, unusedCost, unusedItems, applied := s.applyBatchLocked(frames, cost, items)
	s.releasePendingLocked(unusedCost, unusedItems)
	s.backendWG.Add(len(start))
	if applied {
		*last = sequence
		if in.retryable {
			*digest = in.digest
		}
	} else {
		s.closeLocked()
	}
	s.mu.Unlock()
	for _, connection := range stop {
		connection.close()
	}
	for _, connection := range start {
		go connection.run()
	}
	if !applied {
		return 0, ErrClosed
	}
	if s.manager != nil {
		s.manager.counters.up.Add(uint64(len(in.body)))
	}
	return sequence, nil
}

func (s *Session) replayUploadLocked(id uint32, sequence uint64, want, got [sha256.Size]byte) (uint64, error) {
	if want != got {
		return s.rejectUploadLocked(id)
	}
	s.mu.Unlock()
	return sequence, nil
}

// Hold the session lock through protocol failure so no later upload can commit
// between rejecting an invalid batch and retiring the affected carrier.
func (s *Session) rejectUploadLocked(id uint32) (uint64, error) {
	if s.carrier == config.CarrierWebSocketLanes {
		stream := s.detachWebSocketLaneLocked(id)
		s.mu.Unlock()
		if stream != nil {
			stream.close()
		}
	} else {
		s.closeLocked()
		s.mu.Unlock()
	}
	return 0, ErrProtocol
}
