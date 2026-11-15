package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/http"
	"github.com/rityak/quri/config"
	"github.com/rityak/quri/route"
	"github.com/rityak/quri/transport"
	"golang.org/x/sync/errgroup"
)

// Factory authorizes one fixed outbound for this principal and configuration.
type Factory func(context.Context, string, Request) (route.Route, error)

type serverSession struct {
	ready  chan struct{}
	route  route.Route
	err    error
	active atomic.Int64
}

// Server is an HTTP handler. It never loads global miray rules or configuration.
type Server struct {
	factory  Factory
	limits   config.Config
	logger   *slog.Logger
	mu       sync.Mutex
	sessions map[*transport.Peer]*serverSession
}

// NewServer bounds configuration work and snapshots the shared resource limits.
func NewServer(factory Factory, limits config.Config, logger *slog.Logger) (*Server, error) {
	limits = limits.WithDefaults()
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	if factory == nil {
		return nil, errors.New("missing route factory")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Server{factory: factory, limits: limits, logger: logger, sessions: make(map[*transport.Peer]*serverSession)}, nil
}

// ServeHTTP handles configuration and authorized TCP/UDP flows.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	peer := transport.PeerFromContext(r.Context())
	if peer == nil || peer.Principal() == "" {
		http.Error(w, "request rejected", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == configurationPath {
		s.configure(w, r, peer)
		return
	}
	if r.Method == http.MethodHead || r.Method == http.MethodGet {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodConnect {
		http.Error(w, "request rejected", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	state := s.sessions[peer]
	s.mu.Unlock()
	if state == nil {
		http.Error(w, "session unavailable", http.StatusConflict)
		return
	}
	select {
	case <-state.ready:
	case <-r.Context().Done():
		return
	}
	if state.err != nil {
		http.Error(w, "session unavailable", http.StatusConflict)
		return
	}
	if state.active.Add(1) > int64(s.limits.MaxStreams) {
		state.active.Add(-1)
		http.Error(w, "busy", http.StatusTooManyRequests)
		return
	}
	defer state.active.Add(-1)
	isUDP := r.Proto == "connect-udp" || r.Header.Get(":protocol") == "connect-udp"
	if isUDP {
		s.serveUDP(w, r, state.route)
		return
	}
	if err := route.ValidateAddress(r.Host); err != nil {
		http.Error(w, "invalid destination", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.limits.OpenTimeout)
	target, err := state.route.DialContext(ctx, r.Host)
	cancel()
	if err != nil {
		http.Error(w, "destination unavailable", http.StatusBadGateway)
		return
	}
	stop := context.AfterFunc(r.Context(), func() { _ = target.Close() }) //nolint:errcheck // Cancellation cleanup cannot change the completed operation result.
	defer stop()
	tunnel, err := transport.Accept(w, r, false, s.limits.MaxDatagram)
	if err != nil {
		_ = target.Close() //nolint:errcheck // Cancellation cleanup cannot change the completed operation result.
		s.logger.Debug("accept TCP tunnel failed", "error", err)
		return
	}
	if err := route.Relay(tunnel, target); err != nil {
		s.logger.Debug("TCP relay ended", "error", err)
	}
}

func (s *Server) configure(w http.ResponseWriter, r *http.Request, peer *transport.Peer) {
	var request Request
	data, err := io.ReadAll(io.LimitReader(r.Body, int64(s.limits.MaxControl)+1))
	if err != nil || len(data) > s.limits.MaxControl {
		http.Error(w, "configuration too large", http.StatusRequestEntityTooLarge)
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || request.Namespace == "" || len(request.Namespace) > 128 || request.Version == 0 || decoder.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid configuration", http.StatusBadRequest)
		return
	}
	state := &serverSession{ready: make(chan struct{})}
	s.mu.Lock()
	if _, exists := s.sessions[peer]; exists || len(s.sessions) >= s.limits.MaxConnections {
		s.mu.Unlock()
		http.Error(w, "session already configured or busy", http.StatusConflict)
		return
	}
	s.sessions[peer] = state
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), s.limits.OpenTimeout)
	state.route, state.err = s.factory(ctx, peer.Principal(), request)
	cancel()
	if state.err == nil && state.route == nil {
		state.err = errors.New("factory returned no route")
	}
	close(state.ready)
	context.AfterFunc(peer.Context(), func() {
		s.mu.Lock()
		delete(s.sessions, peer)
		s.mu.Unlock()
		if state.route != nil {
			if err := state.route.Close(); err != nil {
				s.logger.Debug("close outbound failed", "error", err)
			}
		}
	})
	if state.err != nil {
		http.Error(w, "configuration rejected", http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) serveUDP(w http.ResponseWriter, r *http.Request, outbound route.Route) {
	address, err := transport.UDPTarget(r)
	if err != nil {
		http.Error(w, "invalid UDP request", http.StatusBadRequest)
		return
	}
	addr, err := route.UDPAddress(address)
	if err != nil {
		http.Error(w, "invalid UDP destination", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.limits.OpenTimeout)
	target, err := outbound.ListenPacket(ctx)
	cancel()
	if err != nil {
		http.Error(w, "destination unavailable", http.StatusBadGateway)
		return
	}
	tunnel, err := transport.Accept(w, r, true, s.limits.MaxDatagram)
	if err != nil {
		_ = target.Close() //nolint:errcheck // Cancellation cleanup cannot change the completed operation result.
		s.logger.Debug("accept UDP tunnel failed", "error", err)
		return
	}
	group, ctx := errgroup.WithContext(r.Context())
	abort := func() { _ = target.Close(); _ = tunnel.Close() } //nolint:errcheck // Both workers must unblock before the handler returns. Cancellation cleanup cannot change the completed operation result.
	abortDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { abort(); close(abortDone) })
	defer func() {
		if !stop() {
			<-abortDone
		}
	}()
	defer abort()
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	group.Go(func() error {
		interval := s.limits.IdleTimeout / 2
		if interval < time.Nanosecond {
			interval = time.Nanosecond
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case now := <-ticker.C:
				if now.Sub(time.Unix(0, lastActivity.Load())) >= s.limits.IdleTimeout {
					return errors.New("UDP tunnel idle")
				}
			}
		}
	})
	group.Go(func() error {
		buf := make([]byte, s.limits.MaxDatagram)
		for {
			n, err := tunnel.ReceiveDatagram(ctx, buf)
			if err != nil {
				return err
			}
			if _, err := target.WriteTo(buf[:n], addr); err != nil {
				return err
			}
			lastActivity.Store(time.Now().UnixNano())
		}
	})
	group.Go(func() error {
		buf := make([]byte, s.limits.MaxDatagram+1)
		for {
			n, _, err := target.ReadFrom(buf)
			if err != nil {
				return err
			}
			if n > s.limits.MaxDatagram {
				continue
			}
			if err := tunnel.SendDatagram(ctx, buf[:n]); err != nil && !errors.Is(err, transport.ErrDatagramTooLarge) {
				return err
			}
			lastActivity.Store(time.Now().UnixNano())
		}
	})
	if err := group.Wait(); err != nil && !errors.Is(err, net.ErrClosed) {
		s.logger.Debug("UDP relay ended", "error", err)
	}
}
