//go:build !purego

package tproxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"golang.org/x/sys/unix"
)

func TestVAESGuardPages(t *testing.T) {
	if !useVAES {
		t.Skip("VAES unavailable")
	}
	page := unix.Getpagesize()
	srcPage, dstPage := guardedPage(t, page), guardedPage(t, page)
	key, iv := [32]byte{1, 2, 3, 4}, [aes.BlockSize]byte{5, 6, 7, 8}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []struct {
		name      string
		sizes     []int
		reference func() func([]byte, []byte)
		assembly  func() func([]byte, []byte)
	}{
		{"CTR", []int{vaesBatch - 1, vaesBatch, vaesBatch + 1, page},
			func() func([]byte, []byte) { return standardCTR(key, iv).XORKeyStream },
			func() func([]byte, []byte) { return newVAESCTR(key, iv).XORKeyStream }},
		{"CBC", []int{vaesBatch - aes.BlockSize, vaesBatch, vaesBatch + aes.BlockSize, page},
			func() func([]byte, []byte) { return cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks },
			func() func([]byte, []byte) { return newVAESCBCDecrypter(key, iv).CryptBlocks }},
	} {
		t.Run(mode.name, func(t *testing.T) {
			for _, size := range mode.sizes {
				input := make([]byte, size)
				for i := range input {
					input[i] = byte(i ^ (i >> 8))
				}
				want := make([]byte, size)
				mode.reference()(want, input)
				for _, offset := range []int{0, page - size} {
					src := srcPage[offset : offset+size : offset+size]
					dst := dstPage[offset : offset+size : offset+size]
					copy(src, input)
					mode.assembly()(dst, src)
					if !bytes.Equal(dst, want) || !bytes.Equal(src, input) {
						t.Fatalf("size %d offset %d: separate buffer mismatch", size, offset)
					}
					mode.assembly()(src, src)
					if !bytes.Equal(src, want) {
						t.Fatalf("size %d offset %d: in-place buffer mismatch", size, offset)
					}
				}
			}
		})
	}
}

func guardedPage(t *testing.T, page int) []byte {
	t.Helper()
	mapping, err := unix.Mmap(-1, 0, 3*page, unix.PROT_NONE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Munmap(mapping); err != nil {
			t.Error(err)
		}
	})
	accessible := mapping[page : 2*page : 2*page]
	if err := unix.Mprotect(accessible, unix.PROT_READ|unix.PROT_WRITE); err != nil {
		t.Fatal(err)
	}
	return accessible
}
