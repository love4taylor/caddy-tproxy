package tproxy

import (
	"encoding/hex"
	"net/netip"
	"testing"
)

func TestMiddleIPv4KeyVector(t *testing.T) {
	var peerNonce, localNonce [16]byte
	for i := range peerNonce {
		peerNonce[i], localNonce[i] = byte(i), byte(240+i)
	}
	var secret [128]byte
	for i := range secret {
		secret[i] = byte(i)
	}
	keys := middleSessionKeys(peerNonce, localNonce, 0x68010203,
		netip.MustParseAddrPort("192.0.2.17:53429"), netip.MustParseAddrPort("203.0.113.11:443"), &secret)
	for direction, want := range [2][2]string{
		{"f003bf71bf297856af2d5787f540bd00f786c1fe2d7a0f3329da904c7df2f2b2", "62a4e78e0c90adc3a2cd2f9c638cccc0"},
		{"97f8a4becb895fa994b1e1f562f533b79ceae388aec4cdc6a7607493bacfcf02", "bb0f78a42ffefab7edb0ba3dbc5659a1"},
	} {
		if hex.EncodeToString(keys[direction].key[:]) != want[0] || hex.EncodeToString(keys[direction].iv[:]) != want[1] {
			t.Fatalf("direction %d produced incompatible RPC keys", direction)
		}
	}
}
