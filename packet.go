package quri

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/metacubex/quic-go"
)

const packetHeader = 24

type datagram struct {
	data    []byte
	address string
}
type counters struct{ received, sent, invalid, expired, overflow atomic.Uint64 }

// Statistics counts transport messages and locally detected UDP drops.
// QUIC losses and kernel drops are not included in these application counters.
type Statistics struct{ Received, Sent, Invalid, Expired, Overflow uint64 }

// Statistics returns a concurrency-safe snapshot of application counters.
func (s *Session) Statistics() Statistics {
	return Statistics{s.stats.received.Load(), s.stats.sent.Load(), s.stats.invalid.Load(), s.stats.expired.Load(), s.stats.overflow.Load()}
}

// PacketConn implements net.PacketConn with association-scoped unreliable delivery.
// A short receive buffer returns io.ErrShortBuffer and consumes the datagram.
type PacketConn struct {
	session                     *Session
	stream                      *quic.Stream
	id                          uint64
	next                        atomic.Uint64
	queue                       chan datagram
	done                        chan struct{}
	writeGate                   chan struct{}
	mu                          sync.Mutex
	closed                      bool
	readDeadline, writeDeadline time.Time
	changed                     chan struct{}
	activeCancel                context.CancelFunc
	activeTimer                 *time.Timer
	activeAge                   time.Time
}

func (s *Session) addPacket(st *quic.Stream) (*PacketConn, error) {
	p := &PacketConn{session: s, stream: st, id: uint64(st.StreamID()), queue: make(chan datagram, 16), done: make(chan struct{}), writeGate: make(chan struct{}, 1), changed: make(chan struct{})}
	p.writeGate <- struct{}{}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.draining {
		return nil, ErrDraining
	}
	if len(s.packets) >= maxAssociations {
		return nil, ErrLimit
	}
	s.packets[p.id] = p
	return p, nil
}

// ListenPacket opens a destination-independent UDP association.
func (s *Session) ListenPacket(ctx context.Context) (*PacketConn, error) {
	if err := s.reserveOpen(); err != nil {
		return nil, err
	}
	defer s.releaseOpen()
	st, err := s.open(ctx, "udp", "")
	if err != nil {
		return nil, err
	}
	p, err := s.addPacket(st)
	if err != nil {
		st.CancelRead(1)
		st.CancelWrite(1)
		return nil, err
	}
	s.wg.Add(1)
	go func() { defer s.wg.Done(); var b [1]byte; st.Read(b[:]); p.Close() }()
	return p, nil
}

func (p *PacketConn) deliver(d datagram) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		p.session.releaseDatagramBytes(int64(len(d.data)))
		return
	}
	select {
	case p.queue <- d:
	default:
		p.session.stats.overflow.Add(1)
		p.session.releaseDatagramBytes(int64(len(d.data)))
	}
}

func (p *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		p.mu.Lock()
		deadline, changed, closed := p.readDeadline, p.changed, p.closed
		p.mu.Unlock()
		if closed {
			return 0, nil, net.ErrClosed
		}
		var timeout <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		var d datagram
		var got bool
		var err error
		select {
		case d = <-p.queue:
			got = true
		case <-p.done:
			err = net.ErrClosed
		case <-timeout:
			err = os.ErrDeadlineExceeded
		case <-changed:
		}
		if timer != nil {
			timer.Stop()
		}
		if err != nil {
			return 0, nil, err
		}
		if !got {
			continue
		}
		n := copy(b, d.data)
		p.session.releaseDatagramBytes(int64(len(d.data)))
		if n < len(d.data) {
			return n, packetAddr(d.address), io.ErrShortBuffer
		}
		return n, packetAddr(d.address), nil
	}
}

func (p *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, ErrProtocol
	}
	address := addr.String()
	if err := validAddress(address); err != nil {
		return 0, err
	}
	if len(b) > maxPayload {
		return 0, ErrLimit
	}
	host, _, _ := net.SplitHostPort(address)
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil && len(b) > 65507 {
		return 0, ErrLimit
	}
	age := time.Now().Add(100 * time.Millisecond)
	for {
		p.mu.Lock()
		closed, changed := p.closed, p.changed
		deadline := p.sendDeadlineLocked(age)
		p.mu.Unlock()
		if closed {
			return 0, net.ErrClosed
		}
		if !time.Now().Before(deadline) {
			return 0, os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(time.Until(deadline))
		acquired := false
		select {
		case <-p.done:
			timer.Stop()
			return 0, net.ErrClosed
		case <-timer.C:
			return 0, os.ErrDeadlineExceeded
		case <-changed:
		case <-p.writeGate:
			acquired = true
		}
		timer.Stop()
		if acquired {
			break
		}
	}
	defer func() { p.writeGate <- struct{}{} }()
	ctx, cancel := context.WithCancel(p.session.conn.Context())
	defer cancel()
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return 0, net.ErrClosed
	}
	p.activeAge = age
	p.activeCancel = cancel
	p.activeTimer = time.AfterFunc(time.Until(p.sendDeadlineLocked(age)), cancel)
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.activeTimer.Stop(); p.activeTimer = nil; p.activeCancel = nil; p.mu.Unlock() }()

	size := 1100 - packetHeader
	first := size - len(address)
	count := 1
	if len(b) > first {
		count += (len(b) - first + size - 1) / size
	}
	if count > 64 {
		return 0, ErrLimit
	}
	id := p.next.Add(1)
	if id == 0 {
		return 0, ErrLimit
	}
	offset := 0
	for index := 0; index < count; index++ {
		capacity := size
		name := ""
		if index == 0 {
			capacity = first
			name = address
		}
		n := len(b) - offset
		if n > capacity {
			n = capacity
		}
		frame := make([]byte, packetHeader+len(name)+n)
		binary.BigEndian.PutUint64(frame[:8], p.id)
		binary.BigEndian.PutUint64(frame[8:16], id)
		binary.BigEndian.PutUint16(frame[16:18], uint16(len(b)))
		binary.BigEndian.PutUint16(frame[18:20], uint16(offset))
		binary.BigEndian.PutUint16(frame[20:22], uint16(len(name)))
		frame[22] = byte(index)
		frame[23] = byte(count)
		copy(frame[24:], name)
		copy(frame[24+len(name):], b[offset:offset+n])
		p.mu.Lock()
		deadline := p.sendDeadlineLocked(age)
		p.mu.Unlock()
		if err := p.session.conn.SendDatagramWithDeadline(ctx, frame, deadline); err != nil {
			if ctx.Err() != nil {
				p.mu.Lock()
				closed := p.closed
				p.mu.Unlock()
				if closed || p.session.conn.Context().Err() != nil {
					return 0, net.ErrClosed
				}
				return 0, os.ErrDeadlineExceeded
			}
			return 0, err
		}
		offset += n
	}
	p.session.stats.sent.Add(1)
	return len(b), nil
}

func (p *PacketConn) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	if p.activeCancel != nil {
		p.activeCancel()
	}
	close(p.done)
	for {
		select {
		case d := <-p.queue:
			p.session.releaseDatagramBytes(int64(len(d.data)))
		default:
			goto drained
		}
	}
drained:
	p.mu.Unlock()
	p.stream.CancelRead(0)
	p.stream.Close()
	p.session.mu.Lock()
	delete(p.session.packets, p.id)
	p.session.notifyLocked()
	p.session.mu.Unlock()
	return nil
}
func (p *PacketConn) LocalAddr() net.Addr { return p.session.conn.LocalAddr() }
func (p *PacketConn) SetDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.readDeadline = t
	p.writeDeadline = t
	if p.activeTimer != nil {
		p.activeTimer.Reset(time.Until(p.sendDeadlineLocked(p.activeAge)))
	}
	close(p.changed)
	p.changed = make(chan struct{})
	return nil
}
func (p *PacketConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.readDeadline = t
	close(p.changed)
	p.changed = make(chan struct{})
	return nil
}
func (p *PacketConn) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.writeDeadline = t
	if p.activeTimer != nil {
		p.activeTimer.Reset(time.Until(p.sendDeadlineLocked(p.activeAge)))
	}
	close(p.changed)
	p.changed = make(chan struct{})
	return nil
}

type messageKey struct{ association, message uint64 }
type assembly struct {
	data             []byte
	address          string
	deadline         time.Time
	count            byte
	mask             uint64
	offsets, lengths [64]uint16
}
type completedMessage struct {
	key   messageKey
	until time.Time
}
type reassembler struct {
	entries   map[messageKey]*assembly
	bytes     int
	completed [128]completedMessage
	next      int
}

func (r *reassembler) clear(s *Session) {
	for key, e := range r.entries {
		s.releaseDatagramBytes(int64(len(e.data)))
		delete(r.entries, key)
	}
	r.bytes = 0
}
func (r *reassembler) expire(s *Session, now time.Time) {
	for key, e := range r.entries {
		if !now.Before(e.deadline) {
			r.remove(s, key)
			s.stats.expired.Add(1)
		}
	}
}
func (r *reassembler) remove(s *Session, key messageKey) {
	if e := r.entries[key]; e != nil {
		r.bytes -= len(e.data)
		s.releaseDatagramBytes(int64(len(e.data)))
		delete(r.entries, key)
	}
}

func (r *reassembler) accept(s *Session, b []byte, now time.Time) {
	invalid := func() { s.stats.invalid.Add(1) }
	if len(b) < packetHeader {
		invalid()
		return
	}
	key := messageKey{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:16])}
	total := int(binary.BigEndian.Uint16(b[16:18]))
	offset := int(binary.BigEndian.Uint16(b[18:20]))
	nameLen := int(binary.BigEndian.Uint16(b[20:22]))
	index, count := b[22], b[23]
	if key.message == 0 || total > maxPayload || count == 0 || count > 64 || index >= count || nameLen > 260 || packetHeader+nameLen > len(b) || (index != 0 && nameLen != 0) {
		invalid()
		return
	}
	address := string(b[24 : 24+nameLen])
	data := b[24+nameLen:]
	if (index == 0 && validAddress(address) != nil) || offset+len(data) > total || (len(data) == 0 && (total != 0 || count != 1 || index != 0)) || (index == 0 && offset != 0) {
		invalid()
		return
	}
	s.mu.Lock()
	packet := s.packets[key.association]
	s.mu.Unlock()
	if packet == nil {
		invalid()
		return
	}
	for _, done := range r.completed {
		if done.key == key && now.Before(done.until) {
			return
		}
	}
	e := r.entries[key]
	if e == nil {
		if len(r.entries) >= 32 || r.bytes+total > 1<<20 || !s.reserveDatagramBytes(int64(total)) {
			s.stats.overflow.Add(1)
			return
		}
		e = &assembly{data: make([]byte, total), deadline: now.Add(300 * time.Millisecond), count: count}
		r.entries[key] = e
		r.bytes += total
	}
	if e.count != count || len(e.data) != total {
		r.remove(s, key)
		invalid()
		return
	}
	bit := uint64(1) << index
	if e.mask&bit != 0 {
		if int(e.offsets[index]) != offset || int(e.lengths[index]) != len(data) || !bytes.Equal(e.data[offset:offset+len(data)], data) || (index == 0 && e.address != address) {
			r.remove(s, key)
			invalid()
		}
		return
	}
	for i := byte(0); i < count; i++ {
		if e.mask&(uint64(1)<<i) != 0 && offset < int(e.offsets[i])+int(e.lengths[i]) && int(e.offsets[i]) < offset+len(data) {
			r.remove(s, key)
			invalid()
			return
		}
	}
	copy(e.data[offset:], data)
	e.offsets[index] = uint16(offset)
	e.lengths[index] = uint16(len(data))
	e.mask |= bit
	if index == 0 {
		e.address = address
	}
	if e.mask != ^uint64(0)>>(64-count) {
		return
	}
	sum := 0
	for i := byte(0); i < count; i++ {
		sum += int(e.lengths[i])
	}
	if sum != total || e.address == "" {
		r.remove(s, key)
		invalid()
		return
	}
	host, _, _ := net.SplitHostPort(e.address)
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil && total > 65507 {
		r.remove(s, key)
		invalid()
		return
	}
	delete(r.entries, key)
	r.bytes -= total
	r.completed[r.next] = completedMessage{key: key, until: now.Add(time.Second)}
	r.next = (r.next + 1) % len(r.completed)
	packet.deliver(datagram{data: e.data, address: e.address})
	s.stats.received.Add(1)
}

func (s *Session) readDatagrams() {
	for {
		ctx, cancel := context.WithTimeout(s.conn.Context(), 50*time.Millisecond)
		b, err := s.conn.ReceiveDatagram(ctx)
		cancel()
		now := time.Now()
		s.assembly.expire(s, now)
		if err != nil {
			if s.conn.Context().Err() != nil {
				return
			}
			if errors.Is(err, context.DeadlineExceeded) {
				continue
			}
			s.Close()
			return
		}
		s.assembly.accept(s, b, now)
	}
}

func (s *Session) relayPackets(p *PacketConn, target net.PacketConn, idle time.Duration) {
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer target.Close()
		b := make([]byte, maxPayload)
		for {
			n, addr, err := p.ReadFrom(b)
			if err != nil {
				return
			}
			target.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err = target.WriteTo(b[:n], addr); err != nil {
				continue
			}
			lastActivity.Store(time.Now().UnixNano())
		}
	}()
	lifetime := make(chan struct{})
	go func() { defer close(lifetime); var b [1]byte; p.stream.Read(b[:]); p.Close(); target.Close() }()
	defer func() { p.Close(); target.Close(); <-done; <-lifetime }()
	b := make([]byte, maxPayload)
	for {
		target.SetReadDeadline(time.Unix(0, lastActivity.Load()).Add(idle))
		n, addr, err := target.ReadFrom(b)
		if err != nil {
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() && time.Since(time.Unix(0, lastActivity.Load())) < idle {
				continue
			}
			return
		}
		lastActivity.Store(time.Now().UnixNano())
		p.WriteTo(b[:n], addr)
	}
}

var _ net.PacketConn = (*PacketConn)(nil)

func (p *PacketConn) sendDeadlineLocked(age time.Time) time.Time {
	if !p.writeDeadline.IsZero() && p.writeDeadline.Before(age) {
		return p.writeDeadline
	}
	return age
}
