package quri

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	quic "github.com/metacubex/quic-go"
)

// Stream implements net.Conn and preserves independent read and write shutdown.
// Close aborts an unfinished write; call CloseWrite to flush it with FIN.
type Stream struct {
	stream                      *quic.Stream
	session                     *Session
	mu                          sync.Mutex
	readDone, writeDone, closed bool
	once                        sync.Once
}

func (s *Stream) Read(p []byte) (int, error) {
	n, err := s.stream.Read(p)
	if err != nil {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() && s.session.conn.Context().Err() == nil {
			return n, err
		}
		s.mu.Lock()
		s.readDone = true
		s.mu.Unlock()
		s.complete()
	}
	return n, err
}
func (s *Stream) CloseWrite() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	err := s.stream.Close()
	if err == nil {
		s.writeDone = true
	}
	s.completeLocked()
	return err
}
func (s *Stream) CloseRead() error {
	s.stream.CancelRead(0)
	s.mu.Lock()
	s.readDone = true
	s.completeLocked()
	s.mu.Unlock()
	return nil
}
func (s *Stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		s.stream.CancelRead(0)
		if !s.writeDone {
			s.stream.CancelWrite(0)
		}
		s.readDone = true
		s.writeDone = true
		s.completeLocked()
	}
	return nil
}
func (s *Stream) complete() { s.mu.Lock(); defer s.mu.Unlock(); s.completeLocked() }
func (s *Stream) completeLocked() {
	if s.readDone && s.writeDone {
		s.once.Do(func() { s.session.removeStream(s) })
	}
}
func (s *Stream) LocalAddr() net.Addr  { return s.session.conn.LocalAddr() }
func (s *Stream) RemoteAddr() net.Addr { return s.session.conn.RemoteAddr() }

// Relay copies both directions and propagates EOF through CloseWrite. Each
// endpoint is closed after both directions finish; errors abort the other copy.
func Relay(left, right net.Conn) error {
	defer left.Close()
	defer right.Close()
	done := make(chan error, 1)
	copyHalf := func(dst, src net.Conn) error {
		_, err := io.Copy(dst, src)
		if err != nil {
			dst.Close()
			src.Close()
			return err
		}
		if w, ok := dst.(interface{ CloseWrite() error }); ok {
			return w.CloseWrite()
		}
		return dst.Close()
	}
	go func() { done <- copyHalf(left, right) }()
	err := copyHalf(right, left)
	other := <-done
	if err != nil {
		return err
	}
	return other
}

func (s *Stream) Write(p []byte) (int, error)        { return s.stream.Write(p) }
func (s *Stream) SetDeadline(t time.Time) error      { return s.stream.SetDeadline(t) }
func (s *Stream) SetReadDeadline(t time.Time) error  { return s.stream.SetReadDeadline(t) }
func (s *Stream) SetWriteDeadline(t time.Time) error { return s.stream.SetWriteDeadline(t) }
