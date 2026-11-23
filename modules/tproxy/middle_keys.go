package tproxy

import (
	"crypto/md5"
	"crypto/sha1"
	"net/netip"
)

const (
	clientDirection = iota
	serverDirection
)

type middleCipherKey struct {
	key [32]byte
	iv  [16]byte
}

// middleSessionKeys encodes the IPv4 transcript of the legacy middle-end RPC
// protocol. MD5 and SHA-1 are required by its wire format.
func middleSessionKeys(peerNonce, localNonce [16]byte, unix uint32, local, peer netip.AddrPort, secret *[128]byte) [2]middleCipherKey {
	const roleOffset = 42
	var transcript [214]byte
	copy(transcript[:16], peerNonce[:])
	copy(transcript[16:32], localNonce[:])
	le.PutUint32(transcript[32:36], unix)
	le.PutUint32(transcript[36:40], rpcIPv4(peer.Addr()))
	le.PutUint16(transcript[40:roleOffset], local.Port())
	le.PutUint32(transcript[48:52], rpcIPv4(local.Addr()))
	le.PutUint16(transcript[52:54], peer.Port())
	copy(transcript[54:182], secret[:])
	copy(transcript[182:198], peerNonce[:])
	copy(transcript[198:], localNonce[:])
	var keys [2]middleCipherKey
	for direction, role := range [...]string{"CLIENT", "SERVER"} {
		copy(transcript[roleOffset:48], role)
		prefix := md5.Sum(transcript[1:])
		suffix := sha1.Sum(transcript[:])
		copy(keys[direction].key[:12], prefix[:12])
		copy(keys[direction].key[12:], suffix[:])
		keys[direction].iv = md5.Sum(transcript[2:])
	}
	clear(transcript[:])
	return keys
}
