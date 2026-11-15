package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
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
	"golang.org/x/sync/errgroup"
)

type peerKey struct{}

// Peer is connection-local authentication state shared by HTTP requests.
type Peer struct {
	ctx           context.Context
	binding       []byte
	principal     atomic.Pointer[string]
	local, remote net.Addr
}

// Context ends when this connection terminates.
func (p *Peer) Context() context.Context { return p.ctx }

// Principal is empty until a proof succeeds on this connection.
func (p *Peer) Principal() string {
	if p == nil {
		return ""
	}
	if principal := p.principal.Load(); principal != nil {
		return *principal
	}
	return ""
}

// PeerFromContext returns the connection identity attached by Server.
func PeerFromContext(ctx context.Context) *Peer { p, _ := ctx.Value(peerKey{}).(*Peer); return p }

// ServerOptions binds a static website and an authenticated relay handler.
type ServerOptions struct {
	TLS     *tls.Config
	Auth    *auth.Authenticator
	Handler http.Handler
	Website http.Handler
	Limits  config.Config
}

// Server owns both sockets. A missing credential always reaches the website.
type Server struct {
	tcp     net.Listener
	udp     net.PacketConn
	options ServerOptions
	h3      *http3.Server
	active  atomic.Int64
	serving atomic.Bool
}

// NewServer validates before taking ownership of the supplied sockets.
func NewServer(tcp net.Listener, udp net.PacketConn, options ServerOptions) (*Server, error) {
	options.Limits = options.Limits.WithDefaults()
	if err := options.Limits.Validate(); err != nil {
		return nil, err
	}
	if tcp == nil || udp == nil || options.TLS == nil || options.Auth == nil || options.Handler == nil || options.TLS.GetConfigForClient != nil {
		return nil, errors.New("missing HTTP relay server configuration")
	}
	options.TLS = options.TLS.Clone()
	options.TLS.MinVersion = tls.VersionTLS13
	options.TLS.SessionTicketsDisabled = true
	if options.Website == nil {
		options.Website = http.HandlerFunc(staticWebsite)
	}
	s := &Server{tcp: tcp, udp: udp, options: options}
	s.h3 = &http3.Server{TLSConfig: options.TLS, QUICConfig: quicConfig(options.Limits), EnableDatagrams: true, MaxHeaderBytes: options.Limits.MaxControl, Handler: http.HandlerFunc(s.handle)}
	s.h3.ConnContext = func(ctx context.Context, conn *quic.Conn) context.Context {
		state := conn.ConnectionState().TLS
		peer, err := newPeer(ctx, state, conn.LocalAddr(), conn.RemoteAddr())
		if err != nil || s.active.Add(1) > int64(options.Limits.MaxConnections) {
			if err == nil {
				s.active.Add(-1)
			}
			_ = conn.CloseWithError(0x107, "") //nolint:errcheck // Refuse over-limit HTTP connections. Cancellation cleanup cannot change the completed operation result.
			return ctx
		}
		context.AfterFunc(ctx, func() { s.active.Add(-1) })
		return context.WithValue(ctx, peerKey{}, peer)
	}
	return s, nil
}

func newPeer(ctx context.Context, state tls.ConnectionState, local, remote net.Addr) (*Peer, error) {
	binding, err := auth.Binding(state.ExportKeyingMaterial)
	if err != nil {
		return nil, err
	}
	return &Peer{ctx: ctx, binding: binding, local: local, remote: remote}, nil
}

// Serve runs once and joins all owned HTTP/2 connection handlers on shutdown.
func (s *Server) Serve(ctx context.Context) error {
	if !s.serving.CompareAndSwap(false, true) {
		return errors.New("server already served")
	}
	group, ownedCtx := errgroup.WithContext(ctx)
	stop := context.AfterFunc(ownedCtx, func() {
		_ = s.tcp.Close() //nolint:errcheck // Unblock Accept during shutdown. Cancellation cleanup cannot change the completed operation result.
		_ = s.h3.Close()  //nolint:errcheck // Abort owned HTTP/3 connections. Cancellation cleanup cannot change the completed operation result.
		_ = s.udp.Close() //nolint:errcheck // Unblock the QUIC socket reader. Cancellation cleanup cannot change the completed operation result.
	})
	defer stop()
	group.Go(func() error { return s.h3.Serve(s.udp) })
	group.Go(func() error { return s.serveH2(ownedCtx) })
	err := group.Wait()
	if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) serveH2(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	var connections errgroup.Group
	defer func() { cancel(); _ = connections.Wait() }()                                                                                                                //nolint:errcheck // All connection handlers return nil after closing their socket. All workers return nil and report failures through their result channel.
	server := &http2.Server{EnableExtendedConnectProtocol: true, MaxConcurrentStreams: uint32(s.options.Limits.MaxStreams), IdleTimeout: s.options.Limits.IdleTimeout} //nolint:gosec // Config.Validate bounds MaxStreams to 1024.
	for {
		raw, err := s.tcp.Accept()
		if err != nil {
			return err
		}
		if s.active.Add(1) > int64(s.options.Limits.MaxConnections) {
			s.active.Add(-1)
			_ = raw.Close() //nolint:errcheck // No request is admitted above the connection limit. Cancellation cleanup cannot change the completed operation result.
			continue
		}
		connections.Go(func() error {
			defer s.active.Add(-1)
			defer raw.Close() //nolint:errcheck // This handler owns the accepted socket. Cancellation cleanup cannot change the completed operation result.
			connCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			stop := context.AfterFunc(connCtx, func() { _ = raw.Close() }) //nolint:errcheck // Cancellation cleanup cannot change the completed operation result.
			defer stop()
			tc := s.options.TLS.Clone()
			tc.NextProtos = append([]string{"h2"}, tc.NextProtos...)
			conn := tls.Server(raw, tc)
			handshakeCtx, stopHandshake := context.WithTimeout(connCtx, s.options.Limits.HandshakeTimeout)
			err := conn.HandshakeContext(handshakeCtx)
			stopHandshake()
			if err != nil {
				return nil
			}
			state := conn.ConnectionState()
			if state.NegotiatedProtocol != "h2" {
				return nil
			}
			peer, err := newPeer(connCtx, state, conn.LocalAddr(), conn.RemoteAddr())
			if err != nil {
				return nil
			}
			server.ServeConn(conn, &http2.ServeConnOpts{Context: context.WithValue(connCtx, peerKey{}, peer), Handler: http.HandlerFunc(s.handle)})
			return nil
		})
	}
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	peer := PeerFromContext(r.Context())
	if peer == nil {
		s.options.Website.ServeHTTP(w, r)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/" {
		if cookie, err := r.Cookie(authCookie); err == nil {
			if principal, ok := s.options.Auth.Verify(cookie.Value, peer.binding); ok {
				if old := peer.principal.Load(); old == nil {
					peer.principal.CompareAndSwap(nil, &principal)
				}
			}
		}
		s.options.Website.ServeHTTP(w, r)
		return
	}
	if peer.Principal() == "" {
		s.options.Website.ServeHTTP(w, r)
		return
	}
	s.options.Handler.ServeHTTP(w, r)
}

func staticWebsite(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>Welcome</title><body><h1>Welcome</h1><p>This website is online.</p></body></html>\n") //nolint:errcheck // The response is already committed; disconnect errors require no alternate response. The website response is committed; a client disconnect cannot be answered again.
	}
}

// UDPTarget validates the default RFC 9298 URI template and protocol headers.
func UDPTarget(r *http.Request) (string, error) {
	protocol := r.Proto
	if r.ProtoMajor == 2 {
		protocol = r.Header.Get(":protocol")
	}
	if r.Method != http.MethodConnect || protocol != "connect-udp" || r.Header.Get("Capsule-Protocol") != "?1" {
		return "", errProtocol
	}
	const prefix = "/.well-known/masque/udp/"
	if !strings.HasPrefix(r.URL.EscapedPath(), prefix) {
		return "", errProtocol
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.EscapedPath(), prefix), "/")
	if len(parts) != 3 || parts[2] != "" {
		return "", errProtocol
	}
	host, err := url.PathUnescape(parts[0])
	if err != nil {
		return "", errProtocol
	}
	target := net.JoinHostPort(host, parts[1])
	if err := validateTarget(target); err != nil {
		return "", err
	}
	return target, nil
}

// Accept commits a successful tunnel response after routing has succeeded.
func Accept(w http.ResponseWriter, r *http.Request, udp bool, limit int) (Tunnel, error) {
	peer := PeerFromContext(r.Context())
	if peer == nil || peer.Principal() == "" {
		return nil, errors.New("unauthenticated tunnel")
	}
	if udp {
		w.Header().Set("Capsule-Protocol", "?1")
	}
	w.WriteHeader(http.StatusOK)
	if r.ProtoMajor == 3 {
		streamer, ok := w.(http3.HTTPStreamer)
		if !ok {
			return nil, errors.New("missing HTTP/3 stream access")
		}
		return newH3Tunnel(streamer.HTTPStream(), peer.local, peer.remote, func() {}, limit), nil
	}
	writer, ok := w.(interface {
		CloseWrite() error
		FlushError() error
	})
	if !ok {
		return nil, errors.New("HTTP/2 fork lacks half-close support")
	}
	if err := writer.FlushError(); err != nil {
		return nil, err
	}
	abort := func() {
		if setter, ok := w.(interface {
			SetReadDeadline(time.Time) error
			SetWriteDeadline(time.Time) error
		}); ok {
			_ = setter.SetReadDeadline(time.Now())  //nolint:errcheck // Abort both blocked directions before joining them. Cancellation cleanup cannot change the completed operation result.
			_ = setter.SetWriteDeadline(time.Now()) //nolint:errcheck // Cancellation cleanup cannot change the completed operation result.
		}
	}
	return newH2Tunnel(r.Body, &responseBodyWriter{ResponseWriter: w, close: writer.CloseWrite, flush: writer.FlushError}, peer.local, peer.remote, abort, limit), nil
}

type responseBodyWriter struct {
	http.ResponseWriter
	close func() error
	flush func() error
	mu    sync.Mutex
}

func (w *responseBodyWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.ResponseWriter.Write(p)
	if err == nil {
		err = w.flush()
	}
	return n, err
}
func (w *responseBodyWriter) Close() error { w.mu.Lock(); defer w.mu.Unlock(); return w.close() }
