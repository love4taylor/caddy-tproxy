//go:build unix

package config

import (
	"os"

	"golang.org/x/sys/unix"
)

func openCredentialReadOnly(path string) (*os.File, error) {
	// A replaced path must not block before the descriptor can be checked.
	return os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
}
