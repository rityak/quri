package mirayintegration

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/adapter/outbound"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/rityak/quri/route"
)

// Adapter owns one already configured miray outbound; it never loads core rules.
type Adapter struct{ proxy C.ProxyAdapter }

// NewAdapter transfers ownership of a destination-independent HY2/XUDP adapter.
func NewAdapter(proxy C.ProxyAdapter) (*Adapter, error) {
	if proxy == nil {
		return nil, errors.New("missing outbound adapter")
	}
	return &Adapter{proxy: proxy}, nil
}

// NewOutbound parses one VLESS TCP/TLS/REALITY or HY2 share link.
// Other miray transports can be supplied as an already parsed NewAdapter.
func NewOutbound(link string) (*Adapter, error) {
	if len(link) > 16384 || strings.ContainsAny(link, "\r\n\x00") {
		return nil, errors.New("invalid outbound link")
	}
	u, err := url.Parse(link)
	if err != nil || u.User == nil || u.Hostname() == "" {
		return nil, errors.New("invalid outbound link")
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("invalid outbound port")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, errors.New("invalid outbound settings")
	}
	for _, values := range query {
		if len(values) != 1 {
			return nil, errors.New("duplicate outbound setting")
		}
	}
	if query.Get("insecure") != "" && query.Get("insecure") != "0" {
		return nil, errors.New("outbound TLS verification must remain enabled")
	}
	var proxy C.ProxyAdapter
	switch u.Scheme {
	case "vless":
		if _, hasPassword := u.User.Password(); hasPassword {
			return nil, errors.New("invalid VLESS identity")
		}
		if network := query.Get("type"); network != "" && network != "tcp" {
			return nil, errors.New("share-link transport requires a preconfigured miray adapter")
		}
		security := query.Get("security")
		if security != "tls" && security != "reality" {
			return nil, errors.New("VLESS relay requires TLS or REALITY")
		}
		option := outbound.VlessOption{Name: "quri-session", Server: u.Hostname(), Port: int(port), UUID: u.User.Username(), TLS: true, UDP: true, XUDP: true, ServerName: query.Get("sni"), ClientFingerprint: query.Get("fp"), Flow: query.Get("flow"), Encryption: query.Get("encryption")}
		if option.ServerName == "" {
			option.ServerName = u.Hostname()
		}
		if alpn := query.Get("alpn"); alpn != "" {
			option.ALPN = strings.Split(alpn, ",")
		}
		if security == "reality" {
			option.RealityOpts = outbound.RealityOptions{PublicKey: query.Get("pbk"), ShortID: query.Get("sid")}
			if option.RealityOpts.PublicKey == "" {
				return nil, errors.New("REALITY public key is required")
			}
			if option.ClientFingerprint == "" {
				option.ClientFingerprint = "chrome"
			}
		}
		proxy, err = outbound.NewVless(option)
	case "hysteria2", "hy2":
		password := u.User.Username()
		if second, ok := u.User.Password(); ok {
			password += ":" + second
		}
		option := outbound.Hysteria2Option{Name: "quri-session", Server: u.Hostname(), Port: int(port), Password: password, SNI: query.Get("sni"), Obfs: query.Get("obfs"), ObfsPassword: query.Get("obfs-password")}
		if option.SNI == "" {
			option.SNI = u.Hostname()
		}
		proxy, err = outbound.NewHysteria2(option)
	default:
		return nil, errors.New("outbound must be vless, hysteria2 or hy2")
	}
	if err != nil {
		return nil, errors.New("invalid outbound configuration")
	}
	return NewAdapter(proxy)
}

// DialContext delegates a TCP flow and preserves half-close through core wrappers.
func (a *Adapter) DialContext(ctx context.Context, address string) (net.Conn, error) {
	metadata := &C.Metadata{NetWork: C.TCP}
	if err := metadata.SetRemoteAddress(address); err != nil {
		return nil, err
	}
	conn, err := a.proxy.DialContext(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return &adapterConn{Conn: conn}, nil
}

// ListenPacket opens one destination-independent outbound UDP association.
func (a *Adapter) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	return a.proxy.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: netip.IPv4Unspecified()})
}

// Close releases this session's adapter and any owned pools.
func (a *Adapter) Close() error { return a.proxy.Close() }

type adapterConn struct{ net.Conn }

func (c *adapterConn) CloseWrite() error {
	if writer, ok := N.FindUpstream[interface{ CloseWrite() error }](c.Conn, nil); ok {
		return writer.CloseWrite()
	}
	return c.Conn.Close()
}

var _ route.Route = (*Adapter)(nil)
