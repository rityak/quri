// Package session applies immutable outbound configuration to an HTTP connection.
package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/metacubex/http"
	"github.com/rityak/quri/config"
	"github.com/rityak/quri/transport"
)

const configurationPath = "/api/session"

// Request is the only JSON control message; the payload is validated by the host.
type Request struct {
	Namespace string          `json:"namespace"`
	Version   uint32          `json:"version"`
	Payload   json.RawMessage `json:"payload"`
}

// Session owns one authenticated, configured transport connection.
type Session struct {
	conn    *transport.Conn
	limits  config.Config
	mu      sync.Mutex
	packets map[*PacketConn]struct{}
	closed  bool
}

// New authenticates and configures before exposing any TCP or UDP operation.
// On failure it closes conn, including every transport resource.
func New(ctx context.Context, conn *transport.Conn, token string, request Request, limits config.Config) (*Session, error) {
	limits = limits.WithDefaults()
	if err := limits.Validate(); err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	if err := conn.Authenticate(ctx, token); err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	if len(data) > limits.MaxControl {
		return nil, errors.Join(errors.New("configuration too large"), conn.Close())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://relay.invalid"+configurationPath, bytes.NewReader(data))
	if err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := conn.RoundTrip(req)
	if err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, int64(limits.MaxControl)+1))
	err = errors.Join(readErr, response.Body.Close())
	if err == nil && response.StatusCode != http.StatusNoContent {
		err = errors.New("relay rejected session configuration")
	}
	if err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	s := &Session{conn: conn, limits: limits, packets: make(map[*PacketConn]struct{})}
	context.AfterFunc(conn.Context(), func() { _ = s.Close() }) //nolint:errcheck // Transport termination owns association cancellation. Cancellation cleanup cannot change the completed operation result.
	return s, nil
}

// Done ends on connection failure; TCP streams cannot survive a reconnect.
func (s *Session) Done() <-chan struct{} { return s.conn.Context().Done() }

// Protocol returns h3 or h2; UDP over h2 has reliable TCP delivery semantics.
func (s *Session) Protocol() string { return s.conn.Protocol() }

// Probe performs a bounded HTTP health check on this connection.
func (s *Session) Probe(ctx context.Context) error { return s.conn.Probe(ctx) }

// DialContext opens a standard CONNECT stream and detaches after establishment.
func (s *Session) DialContext(ctx context.Context, target string) (net.Conn, error) {
	return s.conn.Open(ctx, target, false)
}

// Close aborts the transport and joins every association's receiver workers.
func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	packets := make([]*PacketConn, 0, len(s.packets))
	for packet := range s.packets {
		packets = append(packets, packet)
	}
	s.mu.Unlock()
	err := s.conn.Close()
	for _, packet := range packets {
		err = errors.Join(err, packet.Close())
	}
	return err
}
