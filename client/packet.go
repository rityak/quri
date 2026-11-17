package client

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/rityak/quri/session"
)

type packetConn struct {
	manager                     *Manager
	ctx                         context.Context
	cancel                      context.CancelFunc
	mu                          sync.Mutex
	current                     *session.Session
	packet                      net.PacketConn
	readDeadline, writeDeadline time.Time
	closed                      bool
}

// ListenPacket creates an association that binds new destination tunnels after
// reconnection. Datagrams already lost with the old connection are not replayed.
func (m *Manager) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || len(m.packets) >= m.limits.MaxUDPTargets {
		return nil, net.ErrClosed
	}
	ownedCtx, cancel := context.WithCancel(m.ctx)
	p := &packetConn{manager: m, ctx: ownedCtx, cancel: cancel}
	m.packets[p] = struct{}{}
	return p, nil
}

func (p *packetConn) bind(ctx context.Context) (net.PacketConn, *session.Session, error) {
	current, err := p.manager.currentSession(ctx)
	if err != nil {
		return nil, nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, nil, net.ErrClosed
	}
	if p.current == current {
		return p.packet, current, nil
	}
	if p.packet != nil {
		if err := p.packet.Close(); err != nil {
			return nil, nil, err
		}
	}
	packet, err := current.ListenPacket(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := errors.Join(packet.SetReadDeadline(p.readDeadline), packet.SetWriteDeadline(p.writeDeadline)); err != nil {
		return nil, nil, errors.Join(err, packet.Close())
	}
	p.current, p.packet = current, packet
	return packet, current, nil
}

func (p *packetConn) ReadFrom(dst []byte) (int, net.Addr, error) {
	for {
		p.mu.Lock()
		deadline, closed := p.readDeadline, p.closed
		p.mu.Unlock()
		if closed {
			return 0, nil, net.ErrClosed
		}
		ctx := p.ctx
		cancel := func() {}
		if !deadline.IsZero() {
			ctx, cancel = context.WithDeadline(ctx, deadline)
		}
		packet, current, err := p.bind(ctx)
		cancel()
		if err != nil {
			return 0, nil, deadlineError(err)
		}
		n, addr, err := packet.ReadFrom(dst)
		if err == nil {
			return n, addr, nil
		}
		select {
		case <-p.ctx.Done():
			return 0, nil, net.ErrClosed
		case <-current.Done():
			continue
		default:
			return n, addr, err
		}
	}
}
func (p *packetConn) WriteTo(data []byte, addr net.Addr) (int, error) {
	p.mu.Lock()
	deadline, closed := p.writeDeadline, p.closed
	p.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	ctx := p.ctx
	cancel := func() {}
	if !deadline.IsZero() {
		ctx, cancel = context.WithDeadline(ctx, deadline)
	}
	defer cancel()
	packet, _, err := p.bind(ctx)
	if err != nil {
		return 0, deadlineError(err)
	}
	return packet.WriteTo(data, addr)
}
func (p *packetConn) Close() error {
	p.cancel()
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	packet := p.packet
	p.mu.Unlock()
	p.manager.mu.Lock()
	delete(p.manager.packets, p)
	p.manager.mu.Unlock()
	if packet != nil {
		return packet.Close()
	}
	return nil
}
func (p *packetConn) LocalAddr() net.Addr { return packetAddress{} }

type packetAddress struct{}

func (packetAddress) Network() string { return linkScheme }
func (packetAddress) String() string  { return linkScheme }
func (p *packetConn) SetReadDeadline(at time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return net.ErrClosed
	}
	p.readDeadline = at
	if p.packet != nil {
		return p.packet.SetReadDeadline(at)
	}
	return nil
}
func (p *packetConn) SetWriteDeadline(at time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return net.ErrClosed
	}
	p.writeDeadline = at
	if p.packet != nil {
		return p.packet.SetWriteDeadline(at)
	}
	return nil
}
func (p *packetConn) SetDeadline(at time.Time) error {
	return errors.Join(p.SetReadDeadline(at), p.SetWriteDeadline(at))
}
func deadlineError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return os.ErrDeadlineExceeded
	}
	return err
}
