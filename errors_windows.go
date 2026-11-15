package quri

import (
	"errors"
	"golang.org/x/sys/windows"
	"syscall"
)

func isConnectionRefused(err error) bool {
	// Windows net errors carry a WSA code, not the Unix-compatible Go sentinel.
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, windows.WSAECONNREFUSED)
}
