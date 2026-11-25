//go:build !purego

package tproxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"crypto/subtle"
	"encoding/binary"
	"math"
	"math/bits"
	"unsafe"

	"golang.org/x/sys/cpu"
)

const (
	vaesBatch       = 16 * aes.BlockSize
	vaes512CBCGroup = 4 * aes.BlockSize
)

var (
	allowVAES  = cpu.X86.HasAES && !fips140.Enabled()
	useVAES256 = allowVAES && cpu.X86.HasAVX && cpu.X86.HasAVX2 && cpuHasVAES()
	useVAES512 = allowVAES && cpu.X86.HasAVX && cpu.X86.HasAVX512 && cpu.X86.HasAVX512F && cpu.X86.HasAVX512BW && cpu.X86.HasAVX512VAES
)

func init() {
	if useVAES512 || useVAES256 {
		newTransportCTR = func(key [32]byte, iv [aes.BlockSize]byte) cipher.Stream {
			return newVAESCTR(key, iv, useVAES512)
		}
		newRPCDecrypter = func(key [32]byte, iv [aes.BlockSize]byte) cipher.BlockMode {
			return newVAESCBCDecrypter(key, iv, useVAES512)
		}
	}
}

type aes256RoundKeys [15][aes.BlockSize]byte

func cpuHasVAES() bool

//go:noescape
func expandAES256(key *[32]byte, rounds *aes256RoundKeys)

//go:noescape
func invertAES256(rounds *aes256RoundKeys)

//go:noescape
func xorVAESCTR(rounds *aes256RoundKeys, dst, src *byte, size int, counters *[4]uint64)

//go:noescape
func xorVAESCTR512(rounds *aes256RoundKeys, dst, src *byte, size int, counters *[4]uint64)

//go:noescape
func decryptVAESCBC(rounds *aes256RoundKeys, dst, src *byte, size int, iv *[aes.BlockSize]byte)

//go:noescape
func decryptVAESCBC512(rounds *aes256RoundKeys, dst, src *byte, size int, iv *[aes.BlockSize]byte)

var zeroVAESBatch [vaesBatch]byte

type vaesCTR struct {
	rounds aes256RoundKeys
	high   uint64
	low    uint64
	spare  [vaesBatch]byte
	unused int
	wide   bool
}

func newVAESCTR(key [32]byte, iv [aes.BlockSize]byte, wide bool) cipher.Stream {
	c := &vaesCTR{
		high: binary.BigEndian.Uint64(iv[:8]),
		low:  binary.BigEndian.Uint64(iv[8:]),
		wide: wide,
	}
	expandAES256(&key, &c.rounds)
	return c
}

func (c *vaesCTR) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("AES-CTR output shorter than input")
	}
	dst = dst[:len(src)]
	if inexactOverlap(dst, src) {
		panic("AES-CTR input and output overlap")
	}
	for len(src) != 0 {
		if n := min(c.unused, len(src)); n != 0 {
			subtle.XORBytes(dst[:n], src[:n], c.spare[vaesBatch-c.unused:])
			c.unused -= n
			dst, src = dst[n:], src[n:]
			continue
		}

		// Process whole batches directly in the output buffer. The SIMD loop
		// adds to the low counter word, so stop before a carry.
		blocks := min(uint64(len(src)/aes.BlockSize), math.MaxUint64-c.low)
		size := int(blocks) * aes.BlockSize &^ (vaesBatch - 1)
		if size != 0 {
			c.xorBatches(dst, src, size)
			c.low += uint64(size / aes.BlockSize)
			dst, src = dst[size:], src[size:]
			continue
		}
		c.refill()
	}
}

func (c *vaesCTR) xorBatches(dst, src []byte, size int) {
	counters := [4]uint64{c.high, c.low, c.high, c.low + 1}
	if c.wide {
		xorVAESCTR512(&c.rounds, &dst[0], &src[0], size, &counters)
	} else {
		xorVAESCTR(&c.rounds, &dst[0], &src[0], size, &counters)
	}
}

func (c *vaesCTR) refill() {
	if c.low <= math.MaxUint64-vaesBatch/aes.BlockSize {
		c.xorBatches(c.spare[:], zeroVAESBatch[:], vaesBatch)
	} else {
		// The first two round keys are the original AES-256 key. Use the
		// standard library for the rare batch that crosses a 64-bit wrap.
		var key [32]byte
		var iv [aes.BlockSize]byte
		copy(key[:16], c.rounds[0][:])
		copy(key[16:], c.rounds[1][:])
		binary.BigEndian.PutUint64(iv[:8], c.high)
		binary.BigEndian.PutUint64(iv[8:], c.low)
		standardCTR(key, iv).XORKeyStream(c.spare[:], zeroVAESBatch[:])
	}
	low, carry := bits.Add64(c.low, vaesBatch/aes.BlockSize, 0)
	c.low = low
	c.high += carry
	c.unused = vaesBatch
}

type cbcDecrypterWithIV interface {
	cipher.BlockMode
	SetIV([]byte)
}

type vaesCBC struct {
	rounds   aes256RoundKeys
	iv       [aes.BlockSize]byte
	fallback cbcDecrypterWithIV
	needsIV  bool
	wide     bool
}

func newVAESCBCDecrypter(key [32]byte, iv [aes.BlockSize]byte, wide bool) cipher.BlockMode {
	decrypt := standardCBCDecrypter(key, iv)
	fallback, ok := decrypt.(cbcDecrypterWithIV)
	if !ok {
		return decrypt
	}
	c := &vaesCBC{iv: iv, fallback: fallback, wide: wide}
	expandAES256(&key, &c.rounds)
	invertAES256(&c.rounds)
	return c
}

func (c *vaesCBC) BlockSize() int { return aes.BlockSize }

func (c *vaesCBC) CryptBlocks(dst, src []byte) {
	if len(src)%aes.BlockSize != 0 || len(dst) < len(src) {
		panic("invalid AES-CBC input or output length")
	}
	dst = dst[:len(src)]
	if inexactOverlap(dst, src) {
		panic("AES-CBC input and output overlap")
	}
	size := len(src) &^ (vaesBatch - 1)
	if c.wide {
		size = len(src) &^ (vaes512CBCGroup - 1)
	}
	if size != 0 {
		if c.wide {
			decryptVAESCBC512(&c.rounds, &dst[0], &src[0], size, &c.iv)
		} else {
			decryptVAESCBC(&c.rounds, &dst[0], &src[0], size, &c.iv)
		}
		c.needsIV = true
		dst, src = dst[size:], src[size:]
	}
	if len(src) != 0 {
		if c.needsIV {
			c.fallback.SetIV(c.iv[:])
			c.needsIV = false
		}
		copy(c.iv[:], src[len(src)-aes.BlockSize:])
		c.fallback.CryptBlocks(dst, src)
	}
}

func inexactOverlap(dst, src []byte) bool {
	if len(dst) == 0 || len(src) == 0 || &dst[0] == &src[0] {
		return false
	}
	d, s := uintptr(unsafe.Pointer(&dst[0])), uintptr(unsafe.Pointer(&src[0]))
	return d < s+uintptr(len(src)) && s < d+uintptr(len(dst))
}
