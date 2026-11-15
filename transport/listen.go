package transport

import (
	"errors"
	"net"
)

const ephemeralBindAttempts = 8

// ListenSockets binds the same local endpoint for TCP and UDP. With port zero,
// TCP's ephemeral choice may be reserved for UDP on Windows, so select again.
func ListenSockets(address string) (net.Listener, net.PacketConn, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, nil, err
	}
	attempts := 1
	if port == "0" {
		attempts = ephemeralBindAttempts
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		tcp, err := net.Listen("tcp", address)
		if err != nil {
			return nil, nil, err
		}
		udp, err := net.ListenPacket("udp", tcp.Addr().String())
		if err == nil {
			return tcp, udp, nil
		}
		lastErr = err
		if closeErr := tcp.Close(); closeErr != nil {
			return nil, nil, errors.Join(err, closeErr)
		}
	}
	return nil, nil, lastErr
}
