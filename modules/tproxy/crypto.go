package tproxy

import (
	"crypto/aes"
	"crypto/cipher"
)

var (
	newTransportCTR = standardCTR
	newRPCDecrypter = standardCBCDecrypter
)

func standardCTR(key [32]byte, iv [aes.BlockSize]byte) cipher.Stream {
	block, _ := aes.NewCipher(key[:])
	return cipher.NewCTR(block, iv[:])
}

func standardCBCDecrypter(key [32]byte, iv [aes.BlockSize]byte) cipher.BlockMode {
	block, _ := aes.NewCipher(key[:])
	return cipher.NewCBCDecrypter(block, iv[:])
}
