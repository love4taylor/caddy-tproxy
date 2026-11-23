package frame

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestFrameWireContract(t *testing.T) {
	wire, _ := hex.DecodeString("01ffffff000000000200010200000003010203040001020000000400000001")
	got, err := ParseAll(wire, MaxPayload)
	if err != nil || len(got) != 3 {
		t.Fatalf("decoded %d frames: %v", len(got), err)
	}
	if got[0].StreamID != MaxStreamID || got[1].StreamID != 258 || got[2].Type != Window {
		t.Fatalf("wrong header values: %v", got)
	}
	for _, item := range got {
		if err := ValidateClientShape(item); err != nil {
			t.Fatal(err)
		}
	}
	if cap(got[1].Payload) != len(got[1].Payload) {
		t.Fatal("payload capacity crosses into a later frame")
	}
	if !bytes.Equal(Encode(Data, 258, []byte{1, 2, 3}), wire[8:19]) {
		t.Fatal("wire encoding changed")
	}
}

func TestFrameRejectsMalformedInput(t *testing.T) {
	for _, entry := range []struct {
		source string
		limit  int
		want   error
	}{
		{"0200000100000001", MaxPayload, ErrIncomplete},
		{"02000001000000020000", 1, ErrPayload},
		{"02000001ffffffff", MaxPayload, ErrPayload},
	} {
		input, _ := hex.DecodeString(entry.source)
		if _, err := ParseAll(input, entry.limit); !errors.Is(err, entry.want) {
			t.Errorf("%s: got %v, want %v", entry.source, err, entry.want)
		}
	}
	if _, err := ParseAll(bytes.Repeat(Encode(Close, 1, nil), MaxBatchFrames+1), MaxPayload); err == nil {
		t.Fatal("frame limit bypassed")
	}
	hello, _ := hex.DecodeString("100000000000000101")
	if ParseHello(hello) != nil || ParseHello(append(hello, 0)) == nil {
		t.Fatal("invalid v1 handshake validation")
	}
	if ValidateClientShape(Frame{Type: Window, StreamID: 42, Payload: make([]byte, 4)}) == nil {
		t.Fatal("zero credit accepted")
	}
}

func TestBatchDecodeAcrossInlineBoundary(t *testing.T) {
	var batch Batch
	limit := len(batch.inline)
	for _, count := range []int{limit, limit + 1, MaxBatchFrames, 1} {
		var wire []byte
		for i := range count {
			wire = append(wire, Encode(Data, uint32(i+1), []byte{byte(i)})...)
		}
		if err := batch.Decode(wire, 1); err != nil {
			t.Fatal(err)
		}
		frames := batch.Frames()
		if len(frames) != count || cap(frames) != count || (batch.overflow != nil) != (count > limit) {
			t.Fatalf("unexpected decoded storage for %d frames: len=%d cap=%d", count, len(frames), cap(frames))
		}
		for i, got := range frames {
			if got.Type != Data || got.StreamID != uint32(i+1) || len(got.Payload) != 1 ||
				cap(got.Payload) != 1 || &got.Payload[0] != &wire[i*(HeaderSize+1)+HeaderSize] {
				t.Fatalf("frame %d in batch of %d changed", i, count)
			}
		}
		if count == 1 && batch.inline[1].Payload != nil {
			t.Fatal("short batch retained an earlier payload in unused storage")
		}
		if count == limit+1 || count == 1 {
			if err := batch.Decode(wire[:len(wire)-1], 1); err != ErrIncomplete || len(batch.Frames()) != 0 || batch.inline[0].Payload != nil {
				t.Fatalf("truncated batch exposed partial results: %v", err)
			}
		}
	}
}

func FuzzParseAll(f *testing.F) {
	f.Add([]byte{2, 0, 0, 1, 0, 0, 0, 1, 42})
	f.Add([]byte{2, 0, 0, 1, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, input []byte) {
		values, err := ParseAll(input, MaxPayload)
		if err != nil {
			return
		}
		offset := 0
		for _, item := range values {
			encoded := Encode(item.Type, item.StreamID, item.Payload)
			if len(encoded) > len(input)-offset || !bytes.Equal(encoded, input[offset:offset+len(encoded)]) {
				t.Fatal("accepted frame does not round-trip")
			}
			offset += len(encoded)
		}
		if offset != len(input) || len(values) > MaxBatchFrames {
			t.Fatal("invalid frame boundary or count")
		}
	})
}
