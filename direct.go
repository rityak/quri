package quri

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// DirectPolicy is an explicit destination allowlist. DNS results are checked
// before dialing their numeric address, preventing DNS rebinding around policy.
type DirectPolicy struct {
	Allowed []netip.Prefix
	Denied  []netip.AddrPort
}

// DirectRoute is the standalone direct outbound, independent of any proxy core.
type DirectRoute struct{ policy DirectPolicy }

// NewDirectRoute snapshots a nonempty, valid IP prefix allowlist.
func NewDirectRoute(policy DirectPolicy) (*DirectRoute, error) {
	if len(policy.Allowed) == 0 {
		return nil, ErrDenied
	}
	for _, prefix := range policy.Allowed {
		if !prefix.IsValid() {
			return nil, ErrProtocol
		}
	}
	return &DirectRoute{policy: DirectPolicy{Allowed: append([]netip.Prefix(nil), policy.Allowed...), Denied: append([]netip.AddrPort(nil), policy.Denied...)}}, nil
}

func (r *DirectRoute) resolve(ctx context.Context, address string) (netip.AddrPort, error) {
	if err := validAddress(address); err != nil {
		return netip.AddrPort{}, err
	}
	host, service, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(service)
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	for _, ip := range ips {
		endpoint := netip.AddrPortFrom(ip.Unmap(), uint16(port))
		allowed := false
		for _, prefix := range r.policy.Allowed {
			if prefix.Contains(endpoint.Addr()) {
				allowed = true
				break
			}
		}
		for _, denied := range r.policy.Denied {
			if denied == endpoint {
				allowed = false
				break
			}
		}
		if allowed {
			return endpoint, nil
		}
	}
	return netip.AddrPort{}, ErrDenied
}

// DialContext resolves and authorizes the destination before opening a socket.
func (r *DirectRoute) DialContext(ctx context.Context, address string) (net.Conn, error) {
	if err := validAddress(address); err != nil {
		return nil, err
	}
	// ControlContext sees the numeric endpoint selected by the standard dialer,
	// preserving Happy Eyeballs without a second DNS lookup after authorization.
	dialer := net.Dialer{ControlContext: func(ctx context.Context, network, address string, _ syscall.RawConn) error {
		endpoint, err := netip.ParseAddrPort(address)
		if err != nil {
			return ErrDenied
		}
		endpoint = netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port())
		for _, denied := range r.policy.Denied {
			if denied == endpoint {
				return ErrDenied
			}
		}
		for _, prefix := range r.policy.Allowed {
			if prefix.Contains(endpoint.Addr()) {
				return nil
			}
		}
		return ErrDenied
	}}
	return dialer.DialContext(ctx, "tcp", address)
}

// ListenPacket creates a UDP socket that checks every destination and accepts
// replies only from endpoints successfully written through this association.
func (r *DirectRoute) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return &directPacket{PacketConn: pc, route: r, peers: make(map[string]struct{})}, nil
}

// Close releases route configuration; flows own their individual sockets.
func (r *DirectRoute) Close() error { return nil }

type directPacket struct {
	net.PacketConn
	route    *DirectRoute
	mu       sync.Mutex
	peers    map[string]struct{}
	deadline time.Time
}

func (p *directPacket) WriteTo(b []byte, addr net.Addr) (int, error) {
	p.mu.Lock()
	deadline := p.deadline
	p.mu.Unlock()
	if deadline.IsZero() {
		deadline = time.Now().Add(5 * time.Second)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	endpoint, err := p.route.resolve(ctx, addr.String())
	if err != nil {
		return 0, err
	}
	p.mu.Lock()
	_, exists := p.peers[endpoint.String()]
	if !exists && len(p.peers) >= 256 {
		p.mu.Unlock()
		return 0, ErrLimit
	}
	p.peers[endpoint.String()] = struct{}{}
	p.mu.Unlock()
	return p.PacketConn.WriteTo(b, net.UDPAddrFromAddrPort(endpoint))
}
func (p *directPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := p.PacketConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}
		p.mu.Lock()
		_, allowed := p.peers[addr.String()]
		p.mu.Unlock()
		if allowed {
			return n, addr, nil
		}
	}
}
func (p *directPacket) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	p.deadline = t
	p.mu.Unlock()
	return p.PacketConn.SetWriteDeadline(t)
}
func (p *directPacket) SetDeadline(t time.Time) error {
	p.mu.Lock()
	p.deadline = t
	p.mu.Unlock()
	return p.PacketConn.SetDeadline(t)
}
