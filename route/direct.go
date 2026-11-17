package route

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/rityak/quri/config"
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

// Resolve authorizes a destination and returns its checked numeric endpoint.
// Proxy hosts must use that endpoint without resolving the name again.
func (r *DirectRoute) Resolve(ctx context.Context, address string) (netip.AddrPort, error) {
	if err := ctx.Err(); err != nil {
		return netip.AddrPort{}, err
	}
	if err := ValidateAddress(address); err != nil {
		return netip.AddrPort{}, err
	}
	if endpoint, err := netip.ParseAddrPort(address); err == nil {
		endpoint = netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port())
		if !r.allows(endpoint) {
			return netip.AddrPort{}, ErrDenied
		}
		return endpoint, nil
	}
	host, service, err := net.SplitHostPort(address)
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := strconv.ParseUint(service, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, ErrProtocol
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	for _, ip := range ips {
		endpoint := netip.AddrPortFrom(ip.Unmap(), uint16(port))
		if r.allows(endpoint) {
			return endpoint, nil
		}
	}
	return netip.AddrPort{}, ErrDenied
}

func (r *DirectRoute) allows(endpoint netip.AddrPort) bool {
	for _, denied := range r.policy.Denied {
		if denied == endpoint {
			return false
		}
	}
	for _, prefix := range r.policy.Allowed {
		if prefix.Contains(endpoint.Addr()) {
			return true
		}
	}
	return false
}

// DialContext resolves and authorizes the destination before opening a socket.
func (r *DirectRoute) DialContext(ctx context.Context, address string) (net.Conn, error) {
	if err := ValidateAddress(address); err != nil {
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
		if r.allows(endpoint) {
			return nil
		}
		return ErrDenied
	}}
	return dialer.DialContext(ctx, "tcp", address)
}

// ListenPacket creates a UDP socket that checks every destination and accepts
// replies only from authorized destinations addressed by this association.
func (r *DirectRoute) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return &directPacket{PacketConn: pc, socket: pc, route: r, peers: make(map[netip.AddrPort]*directPeer)}, nil
}

// Close releases route configuration; flows own their individual sockets.
func (r *DirectRoute) Close() error { return nil }

type directPacket struct {
	net.PacketConn
	socket   *net.UDPConn
	route    *DirectRoute
	mu       sync.Mutex
	peers    map[netip.AddrPort]*directPeer
	deadline time.Time
}

type directPeer struct{ endpoint netip.AddrPort }

func (p *directPeer) Network() string { return "udp" }
func (p *directPeer) String() string  { return p.endpoint.String() }

func (p *directPacket) WriteTo(b []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, ErrProtocol
	}
	var endpoint netip.AddrPort
	switch a := addr.(type) {
	case *net.UDPAddr:
		endpoint = a.AddrPort()
	case *directPeer:
		endpoint = a.endpoint
	default:
		endpoint, _ = netip.ParseAddrPort(addr.String()) //nolint:errcheck // Non-numeric destinations take the bounded DNS path below.
	}
	if endpoint.IsValid() {
		endpoint = netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port())
		if endpoint.Port() == 0 || !p.route.allows(endpoint) {
			return 0, ErrDenied
		}
	} else {
		p.mu.Lock()
		deadline := p.deadline
		p.mu.Unlock()
		if deadline.IsZero() {
			deadline = time.Now().Add(config.DefaultOpenTimeout)
		}
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		var err error
		endpoint, err = p.route.Resolve(ctx, addr.String())
		if err != nil {
			return 0, err
		}
	}
	p.mu.Lock()
	_, exists := p.peers[endpoint]
	if !exists && len(p.peers) >= 256 {
		p.mu.Unlock()
		return 0, ErrLimit
	}
	if !exists {
		p.peers[endpoint] = &directPeer{endpoint: endpoint}
	}
	p.mu.Unlock()
	return p.socket.WriteToUDPAddrPort(b, endpoint)
}
func (p *directPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := p.socket.ReadFromUDPAddrPort(b)
		if err != nil {
			return n, nil, err
		}
		addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
		p.mu.Lock()
		peer, allowed := p.peers[addr]
		p.mu.Unlock()
		if allowed {
			return n, peer, nil
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
