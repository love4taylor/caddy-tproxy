//go:build !unix

package config

import "os"

func openCredentialReadOnly(path string) (*os.File, error) {
	return os.Open(path)
}
