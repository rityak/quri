// Package quri transports TCP streams, UDP datagrams and application messages
// over authenticated QUIC sessions without depending on a proxy core.
package quri

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
)

const (
	alpn             = "quri/1"
	maxApplication   = 1 << 20
	maxControl       = 4*((maxApplication+2)/3) + 1024
	maxOpen          = 4096
	maxCachedReplies = 16
	maxStreams       = 64
	maxAssociations  = 32
	maxPayload       = 65527
)

var (
	// ErrProtocol reports malformed framing or an invalid protocol transition.
	ErrProtocol = errors.New("quri: protocol error")
	// ErrLimit reports a resource limit without retrying an operation.
	ErrLimit = errors.New("quri: resource limit")
	// ErrDenied reports a rejected authentication or routing request.
	ErrDenied = errors.New("quri: access denied")
	// ErrDraining reports an attempt to open work on a draining session.
	ErrDraining = errors.New("quri: session draining")
)

// Request is an application-defined, versioned control message. Payload is
// opaque to quri; the host must authorize and validate its contents.
type Request struct {
	Namespace string `json:"namespace"`
	Version   uint32 `json:"version"`
	Payload   []byte `json:"payload"`
}

type hello struct {
	Version uint32 `json:"version"`
	Token   string `json:"token"`
	UDP     bool   `json:"udp"`
}

type response struct {
	Error   string `json:"error,omitempty"`
	Code    string `json:"code,omitempty"`
	Handle  uint64 `json:"handle,omitempty"`
	Payload []byte `json:"payload,omitempty"`
}

// RemoteError classifies a peer's failure without exposing its internal config.
type RemoteError struct{ Code, Message string }

func (e *RemoteError) Error() string   { return "quri: " + e.Code + ": " + e.Message }
func (e *RemoteError) Timeout() bool   { return e.Code == "timeout" }
func (e *RemoteError) Temporary() bool { return false }
func (e *RemoteError) Is(target error) bool {
	switch target {
	case ErrDenied:
		return e.Code == "denied"
	case ErrLimit:
		return e.Code == "limit"
	case ErrProtocol:
		return e.Code == "protocol"
	case ErrDraining:
		return e.Code == "draining"
	case os.ErrDeadlineExceeded:
		return e.Code == "timeout"
	case syscall.ECONNREFUSED:
		return e.Code == "refused"
	}
	return e.Code == "refused" && isConnectionRefused(target)
}
func failure(err error) response {
	code := "unreachable"
	var network net.Error
	switch {
	case errors.Is(err, ErrDenied):
		code = "denied"
	case errors.Is(err, ErrLimit):
		code = "limit"
	case errors.Is(err, ErrProtocol):
		code = "protocol"
	case errors.Is(err, ErrDraining):
		code = "draining"
	case isConnectionRefused(err):
		code = "refused"
	case errors.As(err, &network) && network.Timeout():
		code = "timeout"
	}
	return response{Error: "operation rejected", Code: code}
}

type open struct {
	Kind    string `json:"kind"`
	Handle  uint64 `json:"handle"`
	Address string `json:"address,omitempty"`
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func writeBlob(w io.Writer, p []byte, limit int) error {
	if len(p) > limit {
		return ErrLimit
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(p)))
	if err := writeAll(w, h[:]); err != nil {
		return err
	}
	return writeAll(w, p)
}

func readBlob(r io.Reader, limit int) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if uint64(n) > uint64(limit) {
		return nil, ErrLimit
	}
	b := make([]byte, int(n))
	_, err := io.ReadFull(r, b)
	return b, err
}

func writeJSON(w io.Writer, v any, limit int) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeBlob(w, b, limit)
}
func readJSON(r io.Reader, v any, limit int) error {
	b, err := readBlob(r, limit)
	if err != nil {
		return err
	}
	if !utf8.Valid(b) {
		return ErrProtocol
	}
	if err = json.Unmarshal(b, v); err != nil {
		return ErrProtocol
	}
	return nil
}

func validAddress(address string) error {
	if len(address) > 260 || !utf8.ValidString(address) {
		return ErrProtocol
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || strings.ContainsAny(host, "\x00\r\n% ") {
		return ErrProtocol
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return ErrProtocol
	}
	return nil
}

// packetAddr preserves domain destinations until the host resolves them.
type packetAddr string

func (a packetAddr) Network() string { return "udp" }
func (a packetAddr) String() string  { return string(a) }

// UDPAddress validates an IPv4, IPv6 or domain endpoint without resolving it.
func UDPAddress(address string) (net.Addr, error) {
	if err := validAddress(address); err != nil {
		return nil, err
	}
	return packetAddr(address), nil
}
