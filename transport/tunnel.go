package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/metacubex/quic-go"
	"github.com/rityak/quri/config"
)

// Tunnel preserves independent TCP shutdown. Datagram methods carry a single
// context-zero UDP payload; h2 uses reliable, ordered DATAGRAM capsules.
type Tunnel interface {
	net.Conn
	CloseWrite() error
	SendDatagram(context.Context, []byte) error
	ReceiveDatagram(context.Context, []byte) (int, error)
}

type h3Stream interface {
	io.ReadWriteCloser
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	SendDatagram([]byte) error
	SendDatagramWithDeadline(context.Context, []byte, time.Time) error
	ReceiveDatagram(context.Context) ([]byte, error)
}

type h3Tunnel struct {
	h3Stream
	local, remote net.Addr
	cancel        context.CancelFunc
	limit         int
	writeMu       sync.Mutex
	writeClosed   atomic.Bool
	sendBuffer    []byte
}

func newH3Tunnel(stream h3Stream, local, remote net.Addr, cancel context.CancelFunc, limit int) *h3Tunnel {
	return &h3Tunnel{h3Stream: stream, local: local, remote: remote, cancel: cancel, limit: limit}
}
func (t *h3Tunnel) LocalAddr() net.Addr  { return t.local }
func (t *h3Tunnel) RemoteAddr() net.Addr { return t.remote }
func (t *h3Tunnel) Write(p []byte) (int, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if t.writeClosed.Load() {
		return 0, net.ErrClosed
	}
	return t.h3Stream.Write(p)
}
func (t *h3Tunnel) CloseWrite() error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	err := t.h3Stream.Close()
	if err == nil {
		t.writeClosed.Store(true)
	}
	return err
}
func (t *h3Tunnel) Close() error {
	// A past deadline unblocks a concurrent Write without discarding accepted data.
	_ = t.h3Stream.SetWriteDeadline(time.Now())
	if !t.writeClosed.Load() {
		if err := t.CloseWrite(); err != nil {
			t.CancelWrite(quic.StreamErrorCode(0x10c))
		}
	}
	t.cancel()
	t.CancelRead(quic.StreamErrorCode(0x10c))
	return nil
}
func (t *h3Tunnel) SendDatagram(ctx context.Context, payload []byte) error {
	if len(payload) > t.limit {
		return ErrDatagramTooLarge
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if cap(t.sendBuffer) < len(payload)+1 {
		t.sendBuffer = make([]byte, len(payload)+1)
	}
	var oversized *quic.DatagramTooLargeError
	deadline, _ := ctx.Deadline()
	expires := time.Now().Add(config.DefaultDatagramLifetime)
	if !deadline.IsZero() && deadline.Before(expires) {
		expires = deadline
	}
	err := t.SendDatagramWithDeadline(ctx, AppendDatagram(t.sendBuffer[:0], payload), expires)
	if errors.As(err, &oversized) {
		return ErrDatagramTooLarge
	}
	return err
}
func (t *h3Tunnel) ReceiveDatagram(ctx context.Context, dst []byte) (int, error) {
	for {
		data, err := t.h3Stream.ReceiveDatagram(ctx)
		if err != nil {
			return 0, err
		}
		payload, err := ParseDatagram(data, t.limit)
		if err != nil {
			continue
		}
		if len(payload) > len(dst) {
			return 0, io.ErrShortBuffer
		}
		return copy(dst, payload), nil
	}
}

type h2Tunnel struct {
	reader                io.ReadCloser
	writer                io.WriteCloser
	local, remote         net.Addr
	cancel                context.CancelFunc
	limit                 int
	readMu                sync.Mutex
	readScratch           [8]byte
	writeMu               sync.Mutex
	sendBuffer            []byte
	mu                    sync.Mutex
	closed                bool
	closeDone             chan struct{}
	readTimer, writeTimer *time.Timer
	writeResult           <-chan error
	requestDone           <-chan struct{}
	closeBudget           time.Duration
}

func newH2Tunnel(reader io.ReadCloser, writer io.WriteCloser, local, remote net.Addr, cancel context.CancelFunc, limit int) *h2Tunnel {
	return &h2Tunnel{reader: reader, writer: writer, local: local, remote: remote, cancel: cancel, limit: limit, closeDone: make(chan struct{})}
}
func (t *h2Tunnel) LocalAddr() net.Addr        { return t.local }
func (t *h2Tunnel) RemoteAddr() net.Addr       { return t.remote }
func (t *h2Tunnel) Read(p []byte) (int, error) { return t.reader.Read(p) }
func (t *h2Tunnel) Write(p []byte) (int, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return t.writer.Write(p)
}
func (t *h2Tunnel) CloseWrite() error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return t.writer.Close()
}
func (t *h2Tunnel) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		<-t.closeDone
		return nil
	}
	t.closed = true
	if t.readTimer != nil {
		t.readTimer.Stop()
	}
	if t.writeTimer != nil {
		t.writeTimer.Stop()
	}
	t.mu.Unlock()
	var err error
	if t.writeResult != nil {
		err = t.writer.Close()
		timer := time.NewTimer(t.closeBudget)
		select {
		case writeErr := <-t.writeResult:
			select {
			case <-t.requestDone:
			default:
				err = errors.Join(err, writeErr)
			}
		case <-t.requestDone:
		case <-timer.C:
			err = errors.Join(err, context.DeadlineExceeded)
		}
		timer.Stop()
	}
	t.cancel()
	err = errors.Join(err, t.reader.Close(), t.writer.Close())
	close(t.closeDone)
	return err
}

func (t *h2Tunnel) abort() error {
	t.cancel()
	return t.Close()
}

// Expiring a client-side h2 deadline aborts this request, because http2.ClientConn
// does not expose resumable per-stream deadlines. Other requests remain usable.
func (t *h2Tunnel) deadline(at time.Time, read bool) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return net.ErrClosed
	}
	timer := &t.writeTimer
	if read {
		timer = &t.readTimer
	}
	if *timer != nil {
		(*timer).Stop()
		*timer = nil
	}
	if !at.IsZero() {
		*timer = time.AfterFunc(time.Until(at), func() { _ = t.abort() }) //nolint:errcheck // Cancellation cleanup cannot change the completed operation result.
	}
	return nil
}
func (t *h2Tunnel) SetReadDeadline(at time.Time) error  { return t.deadline(at, true) }
func (t *h2Tunnel) SetWriteDeadline(at time.Time) error { return t.deadline(at, false) }
func (t *h2Tunnel) SetDeadline(at time.Time) error {
	return errors.Join(t.SetReadDeadline(at), t.SetWriteDeadline(at))
}
func (t *h2Tunnel) SendDatagram(ctx context.Context, payload []byte) error {
	if len(payload) > t.limit {
		return ErrDatagramTooLarge
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = t.Close() }) //nolint:errcheck // Cancellation cleanup cannot change the completed operation result.
	defer stop()
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if cap(t.sendBuffer) < len(payload)+16 {
		t.sendBuffer = make([]byte, len(payload)+16)
	}
	return writeAll(t.writer, AppendCapsule(t.sendBuffer[:0], payload))
}
func (t *h2Tunnel) ReceiveDatagram(ctx context.Context, dst []byte) (int, error) {
	stop := context.AfterFunc(ctx, func() { _ = t.Close() }) //nolint:errcheck // Cancellation cleanup cannot change the completed operation result.
	defer stop()
	t.readMu.Lock()
	defer t.readMu.Unlock()
	return readCapsule(t.reader, dst, t.limit, &t.readScratch)
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
