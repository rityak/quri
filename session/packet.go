package session

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/rityak/quri/route"
	"github.com/rityak/quri/transport"
	"golang.org/x/sync/errgroup"
)

type packetBuffer struct {
	data []byte
	size int
	addr net.Addr
}
type udpTarget struct {
	tunnel transport.Tunnel
	addr   net.Addr
}

// PacketConn maps destinations to bounded standard CONNECT-UDP tunnels.
// Oversized packets are dropped locally without fragmentation or retransmission.
type PacketConn struct {
	session      *Session
	ctx          context.Context
	cancel       context.CancelFunc
	group        errgroup.Group
	pool         sync.Pool
	queue        chan *packetBuffer
	mu           sync.Mutex
	targets      map[string]*udpTarget
	closed       bool
	closeDone    chan struct{}
	readTimer    *time.Timer
	readDeadline time.Time
	readTimeout  <-chan time.Time
	changed      chan struct{}
	writeCtx     context.Context
	writeCancel  context.CancelFunc
}

// ListenPacket creates an association without opening any destination socket.
func (s *Session) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.packets) >= s.limits.MaxUDPTargets {
		return nil, net.ErrClosed
	}
	ownedCtx, cancel := context.WithCancel(s.conn.Context())
	p := &PacketConn{session: s, ctx: ownedCtx, cancel: cancel, queue: make(chan *packetBuffer, s.limits.QueueSize), targets: make(map[string]*udpTarget), closeDone: make(chan struct{}), changed: make(chan struct{}), writeCtx: ownedCtx}
	p.pool.New = func() any { return &packetBuffer{data: make([]byte, s.limits.MaxDatagram)} }
	s.packets[p] = struct{}{}
	return p, nil
}

func (p *PacketConn) target(ctx context.Context, address string) (*udpTarget, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, net.ErrClosed
	}
	if target := p.targets[address]; target != nil {
		return target, nil
	}
	if len(p.targets) >= p.session.limits.MaxUDPTargets {
		return nil, route.ErrLimit
	}
	addr, err := route.UDPAddress(address)
	if err != nil {
		return nil, err
	}
	tunnel, err := p.session.conn.Open(ctx, address, true)
	if err != nil {
		return nil, err
	}
	target := &udpTarget{tunnel: tunnel, addr: addr}
	p.targets[address] = target
	p.group.Go(func() error {
		defer tunnel.Close() //nolint:errcheck // This worker owns the destination tunnel. Cancellation cleanup cannot change the completed operation result.
		defer func() {
			p.mu.Lock()
			if p.targets[address] == target {
				delete(p.targets, address)
			}
			p.mu.Unlock()
		}()
		for {
			buffer := p.pool.Get().(*packetBuffer)
			n, err := tunnel.ReceiveDatagram(p.ctx, buffer.data)
			if err != nil {
				p.pool.Put(buffer)
				return nil // Association survives a destination tunnel expiring.
			}
			buffer.size, buffer.addr = n, addr
			select {
			case p.queue <- buffer:
			default:
				p.pool.Put(buffer)
			}
		}
	})
	return target, nil
}

// WriteTo reports oversize as a local loss and never creates fragments.
func (p *PacketConn) WriteTo(data []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, route.ErrProtocol
	}
	if len(data) > p.session.limits.MaxDatagram {
		return len(data), nil
	}
	p.mu.Lock()
	ctx, closed := p.writeCtx, p.closed
	p.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return 0, packetError(err)
	}
	target, err := p.target(ctx, addr.String())
	if err != nil {
		return 0, packetError(err)
	}
	if err := target.tunnel.SendDatagram(ctx, data); err != nil {
		if errors.Is(err, transport.ErrDatagramTooLarge) {
			return len(data), nil
		}
		return 0, packetError(err)
	}
	return len(data), nil
}

// ReadFrom returns complete datagrams; short buffers consume one packet.
func (p *PacketConn) ReadFrom(dst []byte) (int, net.Addr, error) {
	for {
		p.mu.Lock()
		timeout, changed, closed, deadline := p.readTimeout, p.changed, p.closed, p.readDeadline
		p.mu.Unlock()
		if closed {
			return 0, nil, net.ErrClosed
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return 0, nil, os.ErrDeadlineExceeded
		}
		select {
		case buffer := <-p.queue:
			n, addr := copy(dst, buffer.data[:buffer.size]), buffer.addr
			short := n < buffer.size
			buffer.addr = nil
			p.pool.Put(buffer)
			if short {
				return n, addr, io.ErrShortBuffer
			}
			return n, addr, nil
		case <-p.ctx.Done():
			return 0, nil, net.ErrClosed
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-changed:
		}
	}
}

// Close cancels admission before joining all destination receivers.
func (p *PacketConn) Close() error {
	p.cancel()
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		<-p.closeDone
		return nil
	}
	p.closed = true
	if p.readTimer != nil {
		p.readTimer.Stop()
	}
	if p.writeCancel != nil {
		p.writeCancel()
	}
	targets := make([]*udpTarget, 0, len(p.targets))
	for _, target := range p.targets {
		targets = append(targets, target)
	}
	p.mu.Unlock()
	var err error
	for _, target := range targets {
		err = errors.Join(err, target.tunnel.Close())
	}
	err = errors.Join(err, p.group.Wait())
	p.session.mu.Lock()
	delete(p.session.packets, p)
	p.session.mu.Unlock()
	close(p.closeDone)
	return err
}

// LocalAddr identifies the session transport rather than an OS UDP socket.
func (p *PacketConn) LocalAddr() net.Addr { return packetLocalAddr(p.session.Protocol()) }

type packetLocalAddr string

func (a packetLocalAddr) Network() string { return string(a) }
func (a packetLocalAddr) String() string  { return "quri" }

// SetReadDeadline updates a shared timer only when the caller changes it.
func (p *PacketConn) SetReadDeadline(at time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return net.ErrClosed
	}
	p.readDeadline = at
	if p.readTimer != nil {
		p.readTimer.Stop()
		p.readTimer = nil
	}
	if at.IsZero() {
		p.readTimeout = nil
	} else {
		p.readTimer = time.NewTimer(time.Until(at))
		p.readTimeout = p.readTimer.C
	}
	close(p.changed)
	p.changed = make(chan struct{})
	return nil
}

// SetWriteDeadline shares one cancellable deadline across all packet writes.
func (p *PacketConn) SetWriteDeadline(at time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return net.ErrClosed
	}
	if p.writeCancel != nil {
		p.writeCancel()
	}
	if at.IsZero() {
		p.writeCtx, p.writeCancel = p.ctx, nil
	} else {
		p.writeCtx, p.writeCancel = context.WithDeadline(p.ctx, at)
	}
	return nil
}

// SetDeadline updates receive and send deadlines.
func (p *PacketConn) SetDeadline(at time.Time) error {
	return errors.Join(p.SetReadDeadline(at), p.SetWriteDeadline(at))
}
func packetError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return os.ErrDeadlineExceeded
	}
	return err
}
