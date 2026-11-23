package config

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
)

var errCredentialFileMode = errors.New("must be a regular file accessible only to its owner")

func openCredential(path string) (*os.File, os.FileInfo, error) {
	entry, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if !entry.Mode().IsRegular() || entry.Mode().Perm()&0o077 != 0 {
		return nil, nil, errCredentialFileMode
	}
	file, err := openCredentialReadOnly(path)
	if err != nil {
		return nil, nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, nil, errCredentialFileMode
	}
	if !os.SameFile(entry, opened) {
		_ = file.Close()
		return nil, nil, errors.New("credential file changed while being opened")
	}
	return file, opened, nil
}

func ReadClientSecret(path string) ([]byte, error) {
	file, _, err := openCredential(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	const maxSecretFile = 256
	var text [maxSecretFile + 1]byte
	defer clear(text[:])
	size, err := io.ReadFull(file, text[:])
	if err == nil {
		return nil, errors.New("secret file exceeds 256 bytes")
	}
	if err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	return DecodeSecret(text[:size])
}

func ReadTokenKey(path string) (key [sha256.Size]byte, err error) {
	file, opened, err := openCredential(path)
	if err != nil {
		return key, err
	}
	defer file.Close()
	if opened.Size() != sha256.Size {
		return key, errors.New("token signing key must contain exactly 32 bytes")
	}
	var data [sha256.Size + 1]byte
	defer clear(data[:])
	size, err := io.ReadFull(file, data[:])
	if size != sha256.Size || err != io.ErrUnexpectedEOF {
		return key, errors.New("token signing key changed while being read")
	}
	copy(key[:], data[:])
	return key, nil
}
