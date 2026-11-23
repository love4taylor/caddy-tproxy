package tproxy

import (
	"testing"
	"time"
)

func TestHandshakeReplayWindow(t *testing.T) {
	var window, otherKey handshakeReplays
	now := time.Now()
	var first [32]byte
	if !window.admit(first, now) || window.admit(first, now.Add(time.Second)) {
		t.Fatal("a handshake must be accepted only once within the window")
	}
	if !otherKey.admit(first, now) {
		t.Fatal("the replay window of another key was affected")
	}
	for i := 1; i < handshakeReplayCapacity; i++ {
		var id [32]byte
		le.PutUint64(id[:], uint64(i))
		if !window.admit(id, now.Add(time.Second)) {
			t.Fatalf("window filled at %d", i)
		}
	}
	var next [32]byte
	le.PutUint64(next[:], handshakeReplayCapacity)
	if window.admit(next, now.Add(2*time.Second)) {
		t.Fatal("a full window accepted a new handshake")
	}
	if !window.admit(next, now.Add(handshakeReplayTTL)) {
		t.Fatal("an expired handshake did not free capacity")
	}
	if window.admit([32]byte{1}, now.Add(handshakeReplayTTL)) {
		t.Fatal("an unexpired handshake was evicted")
	}
}

func TestReplayExpiryOrderAfterQueueWrapAndGrowth(t *testing.T) {
	var window handshakeReplays
	start := time.Now()
	for i := range 64 {
		if !window.admit([32]byte{byte(i)}, start.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("initial handshake %d rejected", i)
		}
	}
	now := start.Add(handshakeReplayTTL + 31*time.Second)
	for i := 64; i <= 96; i++ {
		if !window.admit([32]byte{byte(i)}, now) {
			t.Fatalf("handshake %d rejected during wrap and growth", i)
		}
	}
	if window.admit([32]byte{32}, now) || !window.admit([32]byte{32}, now.Add(time.Second)) {
		t.Fatal("wrapped queue lost the exact expiry boundary")
	}
	if window.admit([32]byte{33}, now.Add(time.Second)) || window.admit([32]byte{64}, now.Add(time.Second)) {
		t.Fatal("growing the wrapped queue evicted a live entry")
	}
}

func TestHandshakeWindowSharedForOverlappingConfigurations(t *testing.T) {
	key := [16]byte{19}
	first, _ := handshakeWindows.LoadOrStore(key, new(handshakeReplays))
	defer handshakeWindows.Delete(key)
	var id [32]byte
	if !first.(*handshakeReplays).remember(id) {
		t.Fatal("first handshake was rejected")
	}
	second, _ := handshakeWindows.LoadOrStore(key, new(handshakeReplays))
	defer handshakeWindows.Delete(key)
	if second.(*handshakeReplays).remember(id) {
		t.Fatal("a new configuration discarded the active window")
	}
}
