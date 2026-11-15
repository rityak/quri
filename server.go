package quri

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

// ServerConfig supplies authentication and per-session application policy.
// Callbacks are invoked concurrently across sessions and must honor ctx.
type ServerConfig struct {
	TLS          *tls.Config
	Authenticate func(context.Context, string) (Principal, error)
	Configure    func(context.Context, Principal, Request) (Route, error)
	Application  func(context.Context, Principal, Request) ([]byte, error)
	// OnSession may send messages to the client and must return when ctx ends.
	OnSession func(context.Context, Principal, *Session)
}

// TokenAuthenticator snapshots a principal-to-token map. Tokens must contain at
// least 32 bytes of cryptographically random material encoded for transport.
func TokenAuthenticator(tokens map[Principal]string) (func(context.Context, string) (Principal, error), error) {
	type credential struct {
		principal Principal
		hash      [32]byte
	}
	var credentials []credential
	seen := make(map[[32]byte]bool)
	for principal, token := range tokens {
		if principal == "" || len(token) < 32 || len(token) > 256 {
			return nil, ErrDenied
		}
		hash := sha256.Sum256([]byte(token))
		if seen[hash] {
			return nil, ErrDenied
		}
		seen[hash] = true
		credentials = append(credentials, credential{principal, hash})
	}
	if len(credentials) == 0 {
		return nil, ErrDenied
	}
	return func(ctx context.Context, token string) (Principal, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		hash := sha256.Sum256([]byte(token))
		var result Principal
		for _, c := range credentials {
			if subtle.ConstantTimeCompare(hash[:], c.hash[:]) == 1 {
				result = c.principal
			}
		}
		if result == "" {
			return "", ErrDenied
		}
		return result, nil
	}, nil
}

// Server owns a UDP transport. Serve accepts authenticated sessions until ctx
// expires; Shutdown drains existing sessions and closes the owned socket.
type Server struct {
	cfg           ServerConfig
	listener      *quic.Listener
	transport     *quic.Transport
	socket        net.PacketConn
	mu            sync.Mutex
	sessions      map[*Session]struct{}
	principals    map[Principal]int
	closing       bool
	serving       bool
	wg            sync.WaitGroup
	budget        bufferBudget
	connections   atomic.Int64
	byAddress     map[string]int
	shutdownOnce  sync.Once
	shutdownDone  chan struct{}
	shutdownError error
}

// Listen creates a server, transferring ownership of socket on success.
func Listen(socket net.PacketConn, cfg ServerConfig) (*Server, error) {
	if socket == nil || cfg.TLS == nil || cfg.Authenticate == nil || cfg.Configure == nil || cfg.TLS.GetConfigForClient != nil {
		return nil, ErrProtocol
	}
	tc := cfg.TLS.Clone()
	tc.NextProtos = []string{alpn}
	tc.MinVersion = tls.VersionTLS13
	tc.SessionTicketsDisabled = true
	s := &Server{cfg: cfg, socket: socket, sessions: make(map[*Session]struct{}), principals: make(map[Principal]int), byAddress: make(map[string]int), shutdownDone: make(chan struct{})}
	s.transport = &quic.Transport{Conn: socket, VerifySourceAddress: func(net.Addr) bool { return true }}
	s.transport.ConnContext = func(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
		host, _, err := net.SplitHostPort(info.RemoteAddr.String())
		if err != nil {
			return nil, ErrProtocol
		}
		s.mu.Lock()
		if s.closing || s.connections.Load() >= 64 || s.byAddress[host] >= 8 {
			s.mu.Unlock()
			return nil, ErrLimit
		}
		s.connections.Add(1)
		s.byAddress[host]++
		s.mu.Unlock()
		go func() {
			<-ctx.Done()
			s.mu.Lock()
			s.connections.Add(-1)
			s.byAddress[host]--
			if s.byAddress[host] == 0 {
				delete(s.byAddress, host)
			}
			s.mu.Unlock()
		}()
		return ctx, nil
	}
	listener, err := s.transport.Listen(tc, quicConfig())
	if err != nil {
		s.transport.Close()
		return nil, err
	}
	s.listener = listener
	return s, nil
}

// Addr returns the bound UDP address.
func (s *Server) Addr() net.Addr { return s.listener.Addr() }

// Serve runs once. Canceling ctx initiates cooperative shutdown with a ten-second
// drain budget. Shutdown may also be called concurrently by the owner.
func (s *Server) Serve(ctx context.Context) error {
	s.mu.Lock()
	if s.serving || s.closing {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.serving = true
	s.mu.Unlock()
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			drain, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			s.Shutdown(drain)
		case <-done:
		}
	}()
	defer close(done)
	for {
		c, err := s.listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, quic.ErrServerClosed) {
				return nil
			}
			return err
		}
		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			c.CloseWithError(1, "server closing")
			continue
		}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() { defer s.wg.Done(); s.accept(c) }()
	}
}

func (s *Server) accept(c *quic.Conn) {
	accepted := false
	defer func() {
		if !accepted {
			c.CloseWithError(1, "session rejected")
		}
	}()
	ctx, cancel := context.WithTimeout(c.Context(), 5*time.Second)
	defer cancel()
	control, err := c.AcceptStream(ctx)
	if err != nil {
		return
	}
	if control.StreamID() != 0 {
		return
	}
	control.SetDeadline(time.Now().Add(5 * time.Second))
	var h hello
	if readJSON(control, &h, maxOpen) != nil || h.Version != 1 || !h.UDP || len(h.Token) < 32 || len(h.Token) > 256 || !c.ConnectionState().SupportsDatagrams.Remote {
		return
	}
	principal, err := s.cfg.Authenticate(ctx, h.Token)
	if err != nil || principal == "" {
		writeJSON(control, response{Error: "authentication denied"}, maxOpen)
		return
	}
	s.mu.Lock()
	if s.closing || s.principals[principal] >= 4 {
		s.mu.Unlock()
		return
	}
	s.principals[principal]++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.principals[principal]--
		if s.principals[principal] == 0 {
			delete(s.principals, principal)
		}
		s.mu.Unlock()
	}()
	if writeJSON(control, response{}, maxOpen) != nil {
		return
	}
	control.SetDeadline(time.Time{})
	session := newSession(c, control, &s.budget)
	session.server = s
	session.principal = principal
	if s.cfg.Application != nil {
		session.application = func(ctx context.Context, req Request) ([]byte, error) { return s.cfg.Application(ctx, principal, req) }
	}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return
	}
	s.sessions[session] = struct{}{}
	s.mu.Unlock()
	accepted = true
	session.start()
	if s.cfg.OnSession != nil {
		s.cfg.OnSession(c.Context(), principal, session)
	}
	<-session.finished
	s.mu.Lock()
	delete(s.sessions, session)
	s.mu.Unlock()
}

// Shutdown prevents new connections, cooperatively drains sessions and aborts
// unfinished work at ctx's deadline. It waits for all accepted host handlers.
func (s *Server) Shutdown(ctx context.Context) error {
	s.shutdownOnce.Do(func() { go func() { s.shutdownError = s.shutdown(ctx); close(s.shutdownDone) }() })
	select {
	case <-ctx.Done():
		s.mu.Lock()
		sessions := make([]*Session, 0, len(s.sessions))
		for session := range s.sessions {
			sessions = append(sessions, session)
		}
		s.mu.Unlock()
		for _, session := range sessions {
			session.Close()
		}
		s.transport.Close()
		s.socket.Close()
		return ctx.Err()
	case <-s.shutdownDone:
		return s.shutdownError
	}
}

func (s *Server) shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closing = true
	sessions := make([]*Session, 0, len(s.sessions))
	for session := range s.sessions {
		sessions = append(sessions, session)
	}
	s.mu.Unlock()
	s.listener.Close()
	done := make(chan error, len(sessions))
	for _, session := range sessions {
		go func(session *Session) { done <- session.Shutdown(ctx) }(session)
	}
	var result error
	for i := 0; i < len(sessions); i++ {
		if err := <-done; err != nil && !errors.Is(err, net.ErrClosed) {
			result = err
		}
	}
	s.transport.Close()
	s.socket.Close()
	waited := make(chan struct{})
	go func() { s.wg.Wait(); close(waited) }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-waited:
		return result
	}
}
