package quri

import (
	"context"
	"net"
	"net/netip"
	"time"

	quic "github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

type dialResult struct {
	conn *quic.Conn
	transport *quic.Transport
	socket net.PacketConn
	err error
}

func (r dialResult) close() {
	if r.conn != nil { r.conn.CloseWithError(0, "dial candidate cancelled") }
	if r.transport != nil { r.transport.Close() }
	if r.socket != nil { r.socket.Close() }
}

func dialTransport(ctx context.Context, host string, port uint16, tc *tls.Config, qc *quic.Config, cfg ClientConfig) (*quic.Conn, *quic.Transport, net.PacketConn, error) {
	if len(cfg.Ports) > 15 || cfg.PacketConn != nil && (cfg.ListenPacket != nil || len(cfg.Ports) != 0) {
		return nil, nil, nil, ErrProtocol
	}
	resolve := cfg.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]netip.Addr, error) { return net.DefaultResolver.LookupNetIP(ctx, "ip", host) }
	}
	ips, err := resolve(ctx, host)
	if err != nil { return nil, nil, nil, err }
	ports := []uint16{port}
	for _, other := range cfg.Ports {
		if other == 0 { return nil, nil, nil, ErrProtocol }
		found := false
		for _, existing := range ports { if existing == other { found = true; break } }
		if !found { ports = append(ports, other) }
	}
	var candidates []netip.AddrPort
	for _, p := range ports {
		for _, ip := range ips {
			if ip.IsValid() && ip.Zone() == "" && len(candidates) < 32 {
				candidates = append(candidates, netip.AddrPortFrom(ip.Unmap(), p))
			}
		}
	}
	if len(candidates) == 0 { return nil, nil, nil, ErrDenied }
	if cfg.PacketConn != nil { candidates = candidates[:1] }
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	results := make(chan dialResult, 2)
	next, running := 0, 0
	start := func() {
		address := candidates[next]
		next++
		running++
		go func() {
			r := dialResult{socket: cfg.PacketConn}
			if r.socket == nil {
				if cfg.ListenPacket != nil { r.socket, r.err = cfg.ListenPacket(ctx, address) } else {
					r.socket, r.err = net.ListenUDP("udp", nil)
				}
			}
			if r.err == nil {
				r.transport = &quic.Transport{Conn: r.socket}
				r.transport.SetSingleUse(true)
				r.conn, r.err = r.transport.Dial(ctx, net.UDPAddrFromAddrPort(address), tc, qc)
			}
			if r.err != nil { r.close() }
			results <- r
		}()
	}
	start()
	timer := time.NewTicker(250*time.Millisecond)
	defer timer.Stop()
	var lastErr error
	for running > 0 {
		select {
		case <-ctx.Done():
			cancel()
			for running > 0 { r := <-results; r.close(); running-- }
			return nil, nil, nil, ctx.Err()
		case <-timer.C:
			if running < 2 && next < len(candidates) { start() }
		case r := <-results:
			running--
			if r.err == nil {
				cancel()
				for running > 0 { loser := <-results; loser.close(); running-- }
				return r.conn, r.transport, r.socket, nil
			}
			lastErr = r.err
			if next < len(candidates) { start() }
		}
	}
	return nil, nil, nil, lastErr
}
