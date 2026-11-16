package transport

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/http2"
	quic "github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
	"github.com/rityak/quri/auth"
	"github.com/rityak/quri/config"
	"github.com/rityak/quri/route"
	"golang.org/x/sync/errgroup"
)

const authCookie = "session"

// ClientOptions selects one transport. The client manager races candidates.
type ClientOptions struct {
	TLS          *tls.Config
	Protocol     string
	Limits       config.Config
	DialContext  func(context.Context, string, string) (net.Conn, error)
	ListenPacket func(context.Context, netip.AddrPort) (net.PacketConn, error)
}

// Conn is one authenticated HTTP connection; requests never use a connection pool.
type Conn struct {
	ctx           context.Context
	cancel        context.CancelFunc
	h3            *http3.ClientConn
	quic          *quic.Conn
	h2            *http2.ClientConn
	socket        net.PacketConn
	transport     *quic.Transport
	raw           net.Conn
	binding       []byte
	origin        string
	protocol      string
	limits        config.Config
	once          sync.Once
	closeErr      error
	lifecycle     sync.Mutex
	closed        bool
	active        atomic.Bool
	refused       chan struct{}
	workers       errgroup.Group
	pathGate      chan struct{}
	listenPacket  func(context.Context, netip.AddrPort) (net.PacketConn, error)
	endpoint      netip.AddrPort
	local, remote net.Addr
}

func quicConfig(limits config.Config) *quic.Config {
	return &quic.Config{Versions: []quic.Version{quic.Version1}, EnableDatagrams: true,
		HandshakeIdleTimeout: limits.HandshakeTimeout, MaxIdleTimeout: limits.ConnectionIdleTimeout,
		InitialPacketSize:  1200,
		MaxIncomingStreams: int64(limits.MaxStreams + 4), MaxIncomingUniStreams: 8}
}

// Dial verifies TLS and negotiates exactly h3 or h2. It never sends credentials.
func Dial(ctx context.Context, address string, options ClientOptions) (*Conn, error) {
	limits := options.Limits.WithDefaults()
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	if options.TLS == nil || options.TLS.InsecureSkipVerify {
		return nil, errors.New("verified TLS is required")
	}
	if options.Protocol != "h3" && options.Protocol != "h2" {
		return nil, errors.New("transport must be h3 or h2")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	tc := options.TLS.Clone()
	tc.MinVersion = tls.VersionTLS13
	tc.NextProtos = []string{options.Protocol}
	tc.ClientSessionCache = nil
	if tc.ServerName == "" {
		tc.ServerName = host
	}
	dialCtx, stop := context.WithTimeout(ctx, limits.HandshakeTimeout)
	defer stop()
	ownedCtx, cancel := context.WithCancel(context.Background())
	c := &Conn{ctx: ownedCtx, cancel: cancel, origin: "https://" + net.JoinHostPort(tc.ServerName, "443"), protocol: options.Protocol, limits: limits, refused: make(chan struct{}, 1), pathGate: make(chan struct{}, 1)}
	failed := true
	defer func() {
		if failed {
			_ = c.Close() //nolint:errcheck // Cancellation cleanup cannot change the completed operation result.
		}
	}() // Preserve the establishment error.
	var state tls.ConnectionState
	if options.Protocol == "h3" {
		remote, err := resolveUDP(dialCtx, address)
		if err != nil {
			return nil, err
		}
		c.endpoint = netip.AddrPortFrom(remote.AddrPort().Addr().Unmap(), remote.AddrPort().Port())
		c.listenPacket = options.ListenPacket
		if options.ListenPacket != nil {
			endpoint := remote.AddrPort()
			endpoint = netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port())
			c.socket, err = options.ListenPacket(dialCtx, endpoint)
		} else {
			c.socket, err = net.ListenPacket(remote.Network(), "")
		}
		if err != nil {
			return nil, err
		}
		c.transport = &quic.Transport{Conn: c.socket, ConnectionIDLength: config.DefaultConnectionIDLength}
		c.transport.SetSingleUse(true)
		qc := quicConfig(limits)
		qc.ConnectionRefused = func() bool {
			if !c.active.Load() || c.ctx.Err() != nil {
				return false
			}
			select {
			case c.refused <- struct{}{}:
			default:
			}
			return true
		}
		c.quic, err = c.transport.Dial(dialCtx, remote, tc, qc)
		if err != nil {
			return nil, err
		}
		state = c.quic.ConnectionState().TLS
		c.local, c.remote = c.quic.LocalAddr(), c.quic.RemoteAddr()
		context.AfterFunc(c.quic.Context(), cancel)
		c.h3 = (&http3.Transport{EnableDatagrams: true, DisableCompression: true, MaxResponseHeaderBytes: limits.MaxControl}).NewClientConn(c.quic)
	} else {
		dial := options.DialContext
		if dial == nil {
			dial = new(net.Dialer).DialContext
		}
		raw, err := dial(dialCtx, "tcp", address)
		if err != nil {
			return nil, err
		}
		c.raw = raw
		tlsConn := tls.Client(raw, tc)
		if err := tlsConn.HandshakeContext(dialCtx); err != nil {
			return nil, err
		}
		state = tlsConn.ConnectionState()
		if state.NegotiatedProtocol != "h2" {
			return nil, errors.New("relay did not negotiate h2")
		}
		observed := &observedTLS{Conn: tlsConn, cancel: cancel}
		c.raw = observed
		c.h2, err = (&http2.Transport{DisableCompression: true, MaxReadFrameSize: 16 << 10}).NewClientConn(observed)
		if err != nil {
			return nil, err
		}
	}
	c.binding, err = auth.Binding(state.ExportKeyingMaterial)
	if err != nil {
		return nil, err
	}
	failed = false
	return c, nil
}

func resolveUDP(ctx context.Context, address string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("relay has no IP addresses")
	}
	return net.ResolveUDPAddr("udp", net.JoinHostPort(ips[0].String(), port))
}

type observedTLS struct {
	*tls.Conn
	cancel context.CancelFunc
}

func (c *observedTLS) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.cancel()
	}
	return n, err
}
func (c *observedTLS) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err != nil {
		c.cancel()
	}
	return n, err
}

// Context ends when the underlying connection fails or Close is called.
func (c *Conn) Context() context.Context { return c.ctx }

// Protocol returns the negotiated HTTP transport.
func (c *Conn) Protocol() string { return c.protocol }

// RoundTrip performs a request on this exact connection.
func (c *Conn) RoundTrip(req *http.Request) (*http.Response, error) {
	if c.h3 != nil {
		return c.h3.RoundTrip(req)
	}
	return c.h2.RoundTrip(req)
}

// Authenticate sends only a proof bound to this connection's TLS exporter.
func (c *Conn) Authenticate(ctx context.Context, token string) error {
	proof, err := auth.Proof(token, c.binding)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+"/", nil)
	if err != nil {
		return err
	}
	req.AddCookie(&http.Cookie{Name: authCookie, Value: proof})
	response, err := c.RoundTrip(req)
	if err != nil {
		return err
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, int64(c.limits.MaxControl)+1))
	if err := errors.Join(readErr, response.Body.Close()); err != nil {
		return err
	}
	// The website response intentionally does not disclose authentication state.
	return nil
}

// Open establishes standard HTTP CONNECT or RFC 9298 CONNECT-UDP.
func (c *Conn) Open(ctx context.Context, target string, udp bool) (Tunnel, error) {
	if err := validateTarget(target); err != nil {
		return nil, err
	}
	opCtx, cancel := context.WithTimeout(ctx, c.limits.OpenTimeout)
	defer cancel()
	requestURL := "https://" + target
	if udp {
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			return nil, err
		}
		requestURL = c.origin + "/.well-known/masque/udp/" + url.PathEscape(host) + "/" + port + "/"
	}
	requestCtx, cancelRequest := context.WithCancel(c.ctx)
	stop := context.AfterFunc(opCtx, cancelRequest)
	defer stop()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodConnect, requestURL, nil)
	if err != nil {
		cancelRequest()
		return nil, err
	}
	if udp {
		req.Header.Set("Capsule-Protocol", "?1")
	}
	if c.h3 != nil {
		if udp {
			select {
			case <-c.h3.ReceivedSettings():
			case <-opCtx.Done():
				cancelRequest()
				return nil, opCtx.Err()
			case <-c.ctx.Done():
				cancelRequest()
				return nil, net.ErrClosed
			}
			if !c.h3.Settings().EnableExtendedConnect || !c.h3.Settings().EnableDatagrams {
				cancelRequest()
				return nil, errors.New("relay lacks CONNECT-UDP support")
			}
			req.Proto = "connect-udp"
		}
		stream, err := c.h3.OpenRequestStream(opCtx)
		if err != nil {
			cancelRequest()
			return nil, err
		}
		tunnel := newH3Tunnel(stream, c.local, c.remote, cancelRequest, c.limits.MaxDatagram)
		abort := context.AfterFunc(opCtx, func() { _ = tunnel.Close() }) //nolint:errcheck // Cancellation cleanup cannot change the completed operation result.
		defer abort()
		if err := stream.SendRequestHeader(req); err != nil {
			return nil, errors.Join(err, tunnel.Close())
		}
		response, err := stream.ReadResponse()
		if err != nil {
			return nil, errors.Join(err, tunnel.Close())
		}
		if response.StatusCode != http.StatusOK || (udp && response.Header.Get("Capsule-Protocol") != "?1") {
			return nil, errors.Join(&TunnelError{Status: response.StatusCode}, tunnel.Close())
		}
		return tunnel, nil
	}
	if udp {
		req.Header.Set(":protocol", "connect-udp")
	}
	reader, writer := io.Pipe()
	req.Body = reader
	req.ContentLength = -1
	response, err := c.h2.RoundTrip(req)
	if err != nil {
		cancelRequest()
		return nil, errors.Join(err, reader.Close(), writer.Close())
	}
	if response.StatusCode != http.StatusOK || (udp && response.Header.Get("Capsule-Protocol") != "?1") {
		cancelRequest()
		return nil, errors.Join(&TunnelError{Status: response.StatusCode}, response.Body.Close(), writer.Close())
	}
	return newH2Tunnel(response.Body, writer, c.raw.LocalAddr(), c.raw.RemoteAddr(), cancelRequest, c.limits.MaxDatagram), nil
}

// Close aborts all streams and releases the owned transport and socket.
func (c *Conn) Close() error {
	c.once.Do(func() {
		c.lifecycle.Lock()
		c.closed = true
		c.cancel()
		c.lifecycle.Unlock()
		c.pathGate <- struct{}{}
		var errs []error
		if c.quic != nil {
			errs = append(errs, c.quic.CloseWithError(0, ""))
		}
		if c.h2 != nil {
			errs = append(errs, c.h2.Close())
		} else if c.raw != nil {
			errs = append(errs, c.raw.Close())
		}
		if c.transport != nil {
			errs = append(errs, c.transport.Close())
		}
		if c.socket != nil {
			errs = append(errs, c.socket.Close())
		}
		for _, err := range errs {
			if err != nil && !errors.Is(err, net.ErrClosed) {
				c.closeErr = errors.Join(c.closeErr, err)
			}
		}
		<-c.pathGate
		c.closeErr = errors.Join(c.closeErr, c.workers.Wait())
	})
	return c.closeErr
}

// Activate starts jittered health checks and bounded stale-ICMP verification.
func (c *Conn) Activate() error {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	if c.closed || c.ctx.Err() != nil {
		return net.ErrClosed
	}
	if c.active.Swap(true) {
		return nil
	}
	c.workers.Go(func() error {
		timer := time.NewTimer(c.keepAliveInterval())
		defer timer.Stop()
		var lastProbe time.Time
		for {
			select {
			case <-c.ctx.Done():
				return nil
			case <-c.refused:
				if time.Since(lastProbe) < config.DefaultPathProbeCooldown {
					continue
				}
			case <-timer.C:
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			ctx, cancel := context.WithTimeout(c.ctx, c.limits.OpenTimeout)
			err := c.Probe(ctx)
			cancel()
			if err != nil && c.quic != nil && !errors.Is(err, errHealthResponse) {
				err = c.Migrate(c.ctx)
			}
			if err != nil {
				c.cancel()
				if c.quic != nil {
					_ = c.quic.CloseWithError(0x102, "") //nolint:errcheck // Close joins this worker and collects transport cleanup errors.
				} else {
					_ = c.raw.Close() //nolint:errcheck // Cancel the blocked HTTP/2 connection; Close joins this worker.
				}
				return nil
			}
			lastProbe = time.Now()
			timer.Reset(c.keepAliveInterval())
		}
	})
	return nil
}

func (c *Conn) keepAliveInterval() time.Duration {
	span := c.limits.KeepAliveMax - c.limits.KeepAliveMin
	if span == 0 {
		return c.limits.KeepAliveMin
	}
	return c.limits.KeepAliveMin + time.Duration(rand.Int64N(int64(span))) //nolint:gosec // Scheduling jitter is not a security primitive.
}

func validateTarget(target string) error {
	return route.ValidateAddress(target)
}

// Probe confirms an authenticated HTTP round trip on the current connection.
func (c *Conn) Probe(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.origin+config.ControlPath, nil)
	if err != nil {
		return err
	}
	response, err := c.RoundTrip(req)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusNoContent {
		return errors.Join(errHealthResponse, response.Body.Close())
	}
	return response.Body.Close()
}
