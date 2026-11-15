package mirayintegration

import (
	"context"
	"net"
	"net/netip"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/rityak/quri"
)

// adapterRoute requires a destination-independent packet transport (HY2 or XUDP).
// The host owns policy validation and creates a fresh adapter for each session.
type adapterRoute struct{ proxy C.ProxyAdapter }

func (r *adapterRoute) DialContext(ctx context.Context, address string) (net.Conn, error) {
	metadata := &C.Metadata{NetWork: C.TCP}
	if err := metadata.SetRemoteAddress(address); err != nil {
		return nil, err
	}
	c, err := r.proxy.DialContext(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return &halfCloseConn{Conn: c}, nil
}

func (r *adapterRoute) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	// No destination exists at Open time; each WriteTo supplies its destination.
	return r.proxy.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: netip.IPv4Unspecified()})
}

func (r *adapterRoute) Close() error { return r.proxy.Close() }

type halfCloseConn struct{ net.Conn }

func (c *halfCloseConn) CloseWrite() error {
	if writer, ok := N.FindUpstream[interface{ CloseWrite() error }](c.Conn, nil); ok {
		return writer.CloseWrite()
	}
	return c.Conn.Close()
}

type nextRoute struct{ session *quri.Session }

func (r *nextRoute) DialContext(ctx context.Context, address string) (net.Conn, error) {
	return r.session.DialContext(ctx, address)
}
func (r *nextRoute) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	return r.session.ListenPacket(ctx)
}
func (r *nextRoute) Close() error { return r.session.Close() }

var _ quri.Route = (*adapterRoute)(nil)
var _ quri.Route = (*nextRoute)(nil)
