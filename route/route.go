// Package route defines session-local fixed outbounds without a rules engine.
package route

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Route is immutable after configuration and supports concurrent flows.
type Route interface {
	DialContext(context.Context, string) (net.Conn, error)
	ListenPacket(context.Context) (net.PacketConn, error)
	Close() error
}

// Routing errors do not include outbound secrets.
var (
	ErrDenied   = errors.New("quri: access denied")
	ErrLimit    = errors.New("quri: resource limit")
	ErrProtocol = errors.New("quri: protocol error")
)

// ValidateAddress checks a numeric service and an unambiguous host:port endpoint.
func ValidateAddress(address string) error {
	if len(address) > 260 || !utf8.ValidString(address) {
		return ErrProtocol
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || strings.ContainsAny(host, "\x00\r\n% /?#@\\") {
		return ErrProtocol
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return ErrProtocol
	}
	return nil
}

// Relay copies both directions, forwards FIN independently and joins its worker.
func Relay(left, right net.Conn) error {
	defer left.Close()  //nolint:errcheck // Both flow endpoints are owned by this relay. Cancellation cleanup cannot change the completed operation result.
	defer right.Close() //nolint:errcheck // Cancellation cleanup cannot change the completed operation result.
	done := make(chan error, 1)
	copyHalf := func(dst, src net.Conn) error {
		_, err := io.Copy(dst, src)
		if err == nil {
			if closer, ok := dst.(interface{ CloseWrite() error }); ok {
				err = closer.CloseWrite()
			} else {
				err = dst.Close()
			}
		}
		if err != nil {
			err = errors.Join(err, dst.Close(), src.Close())
		}
		return err
	}
	go func() { done <- copyHalf(left, right) }()
	err := copyHalf(right, left)
	return errors.Join(err, <-done)
}

// UDPAddress retains domain names until an outbound resolves them.
func UDPAddress(address string) (net.Addr, error) {
	if err := ValidateAddress(address); err != nil {
		return nil, err
	}
	return packetAddr(address), nil
}

type packetAddr string

func (a packetAddr) String() string  { return string(a) }
func (a packetAddr) Network() string { return "udp" }
