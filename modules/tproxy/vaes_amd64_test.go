//go:build !purego

package tproxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"strconv"
	"testing"
)

func TestVAESCTRMatchesStandard(t *testing.T) {
	if !useVAES {
		t.Skip("VAES unavailable")
	}
	var key [32]byte
	for i := range key {
		key[i] = byte(i*7 + 11)
	}
	plain := make([]byte, 8195)
	for i := range plain {
		plain[i] = byte(i ^ (i >> 8))
	}
	for _, counter := range []uint64{0, 0x1020304050607080, ^uint64(0) - 21, ^uint64(0)} {
		var iv [16]byte
		binary.BigEndian.PutUint64(iv[:8], ^uint64(0))
		binary.BigEndian.PutUint64(iv[8:], counter)
		want := make([]byte, len(plain))
		standardCTR(key, iv).XORKeyStream(want, plain)
		for _, chunks := range [][]int{{8195}, {1, 0, 15, 41, 1024, 3, 4096}, {256, 256, 32, 255, 257, 4096}} {
			for _, inPlace := range []bool{false, true} {
				stream := newVAESCTR(key, iv)
				if _, ok := stream.(*vaesCTR); !ok {
					t.Fatal("CTR VAES path was not selected")
				}
				got := make([]byte, len(plain))
				src := plain
				if inPlace {
					copy(got, plain)
					src = got
				}
				offset := 0
				for _, n := range chunks {
					stream.XORKeyStream(got[offset:offset+n], src[offset:offset+n])
					offset += n
				}
				stream.XORKeyStream(got[offset:], src[offset:])
				if !bytes.Equal(got, want) {
					t.Fatalf("CTR mismatch at initial counter %x, chunks %v, in-place %t", counter, chunks, inPlace)
				}
			}
		}
	}
}

func TestVAESCBCMatchesStandard(t *testing.T) {
	if !useVAES {
		t.Skip("VAES unavailable")
	}
	var key [32]byte
	var iv [16]byte
	for i := range key {
		key[i] = byte(i*3 + 1)
	}
	for i := range iv {
		iv[i] = byte(i*11 + 4)
	}
	plain := make([]byte, 8192)
	for i := range plain {
		plain[i] = byte(i ^ (i >> 8))
	}
	block, _ := aes.NewCipher(key[:])
	encrypted := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(encrypted, plain)
	for _, chunks := range [][]int{{8192}, {0, 16, 240, 256, 272, 4096, 32}} {
		for _, inPlace := range []bool{false, true} {
			decrypt := newVAESCBCDecrypter(key, iv)
			if _, ok := decrypt.(*vaesCBC); !ok {
				t.Fatal("CBC VAES path was not selected")
			}
			got := make([]byte, len(plain))
			src := encrypted
			if inPlace {
				copy(got, encrypted)
				src = got
			}
			offset := 0
			for _, n := range chunks {
				decrypt.CryptBlocks(got[offset:offset+n], src[offset:offset+n])
				offset += n
			}
			decrypt.CryptBlocks(got[offset:], src[offset:])
			if !bytes.Equal(got, plain) {
				t.Fatalf("CBC mismatch with chunks %v, in-place %t", chunks, inPlace)
			}
		}
	}
}

func BenchmarkMTProxyAES(b *testing.B) {
	for _, mode := range []string{"CTR", "CBCDecrypt"} {
		for _, size := range []int{64, 1024, 16 << 10, 64 << 10} {
			b.Run(mode+"/"+strconv.Itoa(size), func(b *testing.B) {
				b.Run("Standard", func(b *testing.B) { benchmarkAES(b, mode, size, false) })
				if useVAES {
					b.Run("VAES", func(b *testing.B) { benchmarkAES(b, mode, size, true) })
				}
			})
		}
	}
}

func benchmarkAES(b *testing.B, mode string, size int, accelerated bool) {
	key := [32]byte{1}
	iv := [16]byte{2}
	data := make([]byte, size)
	var crypt func([]byte, []byte)
	if mode == "CTR" {
		newCTR := standardCTR
		if accelerated {
			newCTR = newVAESCTR
		}
		crypt = newCTR(key, iv).XORKeyStream
	} else {
		newCBC := standardCBCDecrypter
		if accelerated {
			newCBC = newVAESCBCDecrypter
		}
		crypt = newCBC(key, iv).CryptBlocks
	}
	b.SetBytes(int64(size))
	b.ReportAllocs()
	for b.Loop() {
		crypt(data, data)
	}
}
