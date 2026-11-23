// Package frame implements the binary envelope shared by the WEB carriers.
package frame

import (
	"encoding/binary"
	"errors"
)

const (
	HeaderSize          = 8
	MaxPayload          = 1 << 20
	MaxPongPayload      = 64
	InitialStreamWindow = 4 << 20
	DataChunk           = 1 << 16
	MaxStreamID         = (1 << 24) - 1
	MaxBatchFrames      = 4096
)

type Type byte

const (
	Open    Type = 1
	Data    Type = 2
	Close   Type = 3
	Window  Type = 4
	Ping    Type = 5
	Pong    Type = 6
	Hello   Type = 16
	Welcome Type = 17
	Bye     Type = 31
)

type Frame struct {
	Type     Type
	StreamID uint32
	Payload  []byte
}

var (
	ErrIncomplete = errors.New("truncated WEB proxy frame")
	ErrPayload    = errors.New("WEB proxy payload exceeds maximum")
	errEmptyBatch = errors.New("empty WEB proxy batch")
	errFrameCount = errors.New("too many WEB proxy frames")
	errHello      = errors.New("expected a single v1 HELLO frame")
	errShape      = errors.New("invalid client WEB proxy frame")
	errWindow     = errors.New("invalid WEB proxy window increment")
)

func Encode(kind Type, id uint32, payload []byte) []byte {
	if id > MaxStreamID || uint64(len(payload)) > (1<<32)-1 {
		panic("invalid WEB proxy frame size or stream ID")
	}
	out := make([]byte, HeaderSize+len(payload))
	WriteHeader(out, kind, id)
	copy(out[HeaderSize:], payload)
	return out
}

// WriteHeader initializes the envelope of a slice that also holds its payload.
func WriteHeader(out []byte, kind Type, id uint32) {
	binary.BigEndian.PutUint32(out, uint32(kind)<<24|id)
	binary.BigEndian.PutUint32(out[4:], uint32(len(out)-HeaderSize))
}

// ParseAll borrows payloads from input. The caller must retain input for the
// life of the result. Each payload is capped at its end within the batch.
func ParseAll(input []byte, limit int) ([]Frame, error) {
	if len(input) == 0 {
		return nil, errEmptyBatch
	}
	if limit < 1 || limit > MaxPayload {
		limit = MaxPayload
	}
	end, err := frameEnd(input, limit)
	if err != nil {
		return nil, err
	}
	if end == len(input) {
		return []Frame{view(input, end)}, nil
	}
	_, frames, err := parseFrames(input, limit, nil)
	return frames, err
}

// Batch keeps short decoded batches in caller-owned storage. Decode borrows
// payloads from input until the caller has finished using Frames.
type Batch struct {
	inline   [16]Frame
	used     int
	overflow []Frame
}

func (b *Batch) Decode(input []byte, limit int) error {
	used, overflow, err := parseFrames(input, limit, b.inline[:])
	if err != nil {
		clear(b.inline[:])
	} else if used < b.used {
		clear(b.inline[used:b.used])
	}
	b.used, b.overflow = used, overflow
	return err
}

// Frames is valid until the next Decode on this Batch.
func (b *Batch) Frames() []Frame {
	if b.overflow != nil {
		return b.overflow
	}
	return b.inline[:b.used:b.used]
}

// parseFrames fills scratch first. Longer batches return a complete list
// allocated after validating every header.
func parseFrames(input []byte, limit int, scratch []Frame) (used int, overflow []Frame, err error) {
	if len(input) == 0 {
		return 0, nil, errEmptyBatch
	}
	if limit < 1 || limit > MaxPayload {
		limit = MaxPayload
	}
	for used < len(scratch) && len(input) > 0 {
		end, err := frameEnd(input, limit)
		if err != nil {
			return 0, nil, err
		}
		scratch[used] = view(input, end)
		used++
		input = input[end:]
	}
	if len(input) == 0 {
		return used, nil, nil
	}

	// Count and validate the remaining headers before allocating the result.
	// Large batches need one allocation and malformed batches need none.
	count := used
	for remaining := input; len(remaining) > 0; count++ {
		if count == MaxBatchFrames {
			return 0, nil, errFrameCount
		}
		end, err := frameEnd(remaining, limit)
		if err != nil {
			return 0, nil, err
		}
		remaining = remaining[end:]
	}
	frames := make([]Frame, count)
	copy(frames, scratch[:used])
	for i := used; i < count; i++ {
		end := HeaderSize + int(binary.BigEndian.Uint32(input[4:]))
		frames[i] = view(input, end)
		input = input[end:]
	}
	return used, frames, nil
}

func frameEnd(input []byte, limit int) (int, error) {
	if len(input) < HeaderSize {
		return 0, ErrIncomplete
	}
	size := binary.BigEndian.Uint32(input[4:])
	if size > uint32(limit) {
		return 0, ErrPayload
	}
	end := HeaderSize + int(size)
	if end > len(input) {
		return 0, ErrIncomplete
	}
	return end, nil
}

func view(input []byte, end int) Frame {
	word := binary.BigEndian.Uint32(input)
	return Frame{Type(word >> 24), word & MaxStreamID, input[HeaderSize:end:end]}
}

func ParseHello(input []byte) error {
	if len(input) != 9 || binary.BigEndian.Uint32(input) != uint32(Hello)<<24 ||
		binary.BigEndian.Uint32(input[4:]) != 1 || input[8] != 1 {
		return errHello
	}
	return nil
}

func WindowAmount(payload []byte) (uint32, error) {
	if len(payload) == 4 {
		if amount := binary.BigEndian.Uint32(payload); amount != 0 {
			return amount, nil
		}
	}
	return 0, errWindow
}

func WindowPayload(amount uint32) []byte {
	return binary.BigEndian.AppendUint32(make([]byte, 0, 4), amount)
}

func ValidateClientShape(value Frame) error {
	if value.StreamID == 0 {
		if value.Type == Pong && len(value.Payload) <= MaxPongPayload {
			return nil
		}
		return errShape
	}
	if value.StreamID > MaxStreamID {
		return errShape
	}
	switch value.Type {
	case Open, Close:
		if len(value.Payload) == 0 {
			return nil
		}
	case Data:
		if len(value.Payload) > 0 && len(value.Payload) <= MaxPayload {
			return nil
		}
	case Window:
		_, err := WindowAmount(value.Payload)
		return err
	}
	return errShape
}
