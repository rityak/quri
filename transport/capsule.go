// Package transport carries HTTP CONNECT and CONNECT-UDP over HTTP/3 and HTTP/2.
package transport

import (
	"errors"
	"io"

	"github.com/metacubex/quic-go/quicvarint"
)

// ErrDatagramTooLarge is a local drop; callers must not retry using fragments.
var ErrDatagramTooLarge = errors.New("datagram exceeds the configured or current path MTU")

var errProtocol = errors.New("invalid HTTP datagram or capsule")

// AppendDatagram appends RFC 9298 context zero and one complete UDP payload.
func AppendDatagram(dst, payload []byte) []byte {
	dst = append(dst, 0)
	return append(dst, payload...)
}

// ParseDatagram returns a view of a context-zero payload without allocation.
func ParseDatagram(data []byte, limit int) ([]byte, error) {
	contextID, n, err := quicvarint.Parse(data)
	if err != nil || contextID != 0 {
		return nil, errProtocol
	}
	if len(data)-n > limit {
		return nil, ErrDatagramTooLarge
	}
	return data[n:], nil
}

// AppendCapsule appends one RFC 9297 DATAGRAM capsule using caller-owned space.
func AppendCapsule(dst, payload []byte) []byte {
	dst = append(dst, 0)
	dst = quicvarint.Append(dst, uint64(len(payload)+1))
	return AppendDatagram(dst, payload)
}

// ReadCapsule copies one context-zero payload into dst. Unknown capsule types
// are skipped with bounded storage; oversized capsules terminate the tunnel.
func ReadCapsule(r io.Reader, dst []byte, limit int) (int, error) {
	var scratch [8]byte
	return readCapsule(r, dst, limit, &scratch)
}

func readCapsule(r io.Reader, dst []byte, limit int, scratch *[8]byte) (int, error) {
	if limit < 0 || limit > 65507 {
		return 0, errProtocol
	}
	readVarint := func() (uint64, error) {
		if _, err := io.ReadFull(r, scratch[:1]); err != nil {
			return 0, err
		}
		size := 1 << (scratch[0] >> 6)
		if _, err := io.ReadFull(r, scratch[1:size]); err != nil {
			return 0, err
		}
		n, _, err := quicvarint.Parse(scratch[:size])
		return n, err
	}
	for {
		kind, err := readVarint()
		if err != nil {
			return 0, err
		}
		length, err := readVarint()
		if err != nil {
			return 0, err
		}
		if length > uint64(limit)+8 {
			return 0, ErrDatagramTooLarge
		}
		if kind != 0 {
			if _, err := io.CopyN(io.Discard, r, int64(length)); err != nil { //nolint:gosec // The length is bounded to at most 65515 above.
				return 0, err
			}
			continue
		}
		if length == 0 {
			return 0, errProtocol
		}
		if _, err := io.ReadFull(r, scratch[:1]); err != nil {
			return 0, err
		}
		contextSize := 1 << (scratch[0] >> 6)
		if uint64(contextSize) > length {
			return 0, errProtocol
		}
		if _, err := io.ReadFull(r, scratch[1:contextSize]); err != nil {
			return 0, err
		}
		contextID, _, err := quicvarint.Parse(scratch[:contextSize])
		if err != nil {
			return 0, errProtocol
		}
		payloadSize := int(length) - contextSize //nolint:gosec // The length is bounded to at most 65515 above.
		if payloadSize > limit {
			return 0, ErrDatagramTooLarge
		}
		if contextID != 0 {
			if _, err := io.CopyN(io.Discard, r, int64(payloadSize)); err != nil {
				return 0, err
			}
			continue
		}
		if payloadSize > len(dst) {
			if _, err := io.CopyN(io.Discard, r, int64(payloadSize)); err != nil {
				return 0, err
			}
			return 0, io.ErrShortBuffer
		}
		return io.ReadFull(r, dst[:payloadSize])
	}
}
