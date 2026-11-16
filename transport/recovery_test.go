package transport

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/rityak/quri/auth"
	"github.com/rityak/quri/config"
	"github.com/rityak/quri/internal/testcert"
)

type refusedSocket struct {
	net.PacketConn
	refused, drop atomic.Bool
}

func (s *refusedSocket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := s.PacketConn.ReadFrom(b)
	if s.refused.Swap(false) {
		if err := s.SetReadDeadline(time.Time{}); err != nil {
			return 0, nil, err
		}
		return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: syscall.ECONNREFUSED}
	}
	return n, addr, err
}
func (s *refusedSocket) WriteTo(b []byte, addr net.Addr) (int, error) {
	if s.drop.Load() {
		return len(b), nil
	}
	return s.PacketConn.WriteTo(b, addr)
}

func TestJitteredHealthChecksRequireAuthenticatedResponse(t *testing.T) {
	limits := (config.Config{KeepAliveMin: 10 * time.Millisecond, KeepAliveMax: 25 * time.Millisecond}).WithDefaults()
	c := &Conn{limits: limits}
	intervals := make(map[time.Duration]bool)
	for range 32 {
		interval := c.keepAliveInterval()
		if interval < limits.KeepAliveMin || interval >= limits.KeepAliveMax {
			t.Fatalf("keepalive outside configured bounds: %s", interval)
		}
		intervals[interval] = true
	}
	if len(intervals) == 1 || quicConfig(limits).KeepAlivePeriod != 0 {
		t.Fatal("fixed-period keepalive is still enabled")
	}
	for _, protocol := range []string{"h3", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			serverTLS, clientTLS := testcert.TLS(t)
			tcp, udp, err := ListenSockets("127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			token := strings.Repeat("health-secret-", 3)
			verifier, err := auth.New(map[string]string{testPrincipal: token})
			if err != nil {
				t.Fatal(err)
			}
			var probes atomic.Int64
			server, err := NewServer(tcp, udp, ServerOptions{TLS: serverTLS, Auth: verifier, Website: testWebsite(), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if probes.Add(1) == 1 {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				w.WriteHeader(http.StatusOK)
			})})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			done := make(chan error, 1)
			go func() { done <- server.Serve(ctx) }()
			defer func() {
				cancel()
				if err := <-done; err != nil {
					t.Error(err)
				}
			}()
			conn, err := Dial(ctx, tcp.Addr().String(), ClientOptions{TLS: clientTLS, Protocol: protocol, Limits: limits})
			if err != nil {
				t.Fatal(err)
			}
			defer closeTest(t, conn)
			if err := conn.Authenticate(ctx, token); err != nil {
				t.Fatal(err)
			}
			if err := conn.Activate(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-conn.Context().Done():
			case <-ctx.Done():
				t.Fatal("unhealthy relay did not close without a client manager")
			}
			if probes.Load() != 2 {
				t.Fatalf("unexpected health request count: %d", probes.Load())
			}
		})
	}
}

func TestICMPUsesBoundedAuthenticatedVerification(t *testing.T) {
	for _, blackhole := range []bool{false, true} {
		t.Run(map[bool]string{false: "stale", true: "blackhole"}[blackhole], func(t *testing.T) {
			serverTLS, clientTLS := testcert.TLS(t)
			tcp, udp, err := ListenSockets("127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			token := strings.Repeat("path-secret-", 3)
			verifier, err := auth.New(map[string]string{testPrincipal: token})
			if err != nil {
				t.Fatal(err)
			}
			probes := make(chan struct{}, 2)
			server, err := NewServer(tcp, udp, ServerOptions{TLS: serverTLS, Auth: verifier, Website: testWebsite(), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodHead {
					select {
					case probes <- struct{}{}:
					default:
					}
				}
				w.WriteHeader(http.StatusNoContent)
			})})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			done := make(chan error, 1)
			go func() { done <- server.Serve(ctx) }()
			defer func() {
				cancel()
				if err := <-done; err != nil {
					t.Error(err)
				}
			}()
			var socket *refusedSocket
			conn, err := Dial(ctx, tcp.Addr().String(), ClientOptions{TLS: clientTLS, Protocol: "h3", Limits: config.Config{OpenTimeout: 150 * time.Millisecond}, ListenPacket: func(ctx context.Context, remote netip.AddrPort) (net.PacketConn, error) {
				pc, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					return nil, err
				}
				socket = &refusedSocket{PacketConn: pc}
				return socket, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer closeTest(t, conn)
			if err := conn.Authenticate(ctx, token); err != nil {
				t.Fatal(err)
			}
			if err := conn.Activate(); err != nil {
				t.Fatal(err)
			}
			socket.drop.Store(blackhole)
			socket.refused.Store(true)
			if err := socket.SetReadDeadline(time.Now()); err != nil {
				t.Fatal(err)
			}
			if blackhole {
				select {
				case <-conn.Context().Done():
				case <-ctx.Done():
					t.Fatal("unreachable connection survived its verification budget")
				}
				return
			}
			select {
			case <-probes:
			case <-conn.Context().Done():
				t.Fatal("stale ICMP closed a healthy connection")
			case <-ctx.Done():
				t.Fatal("path verification never reached the authenticated handler")
			}
			if err := conn.Probe(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
