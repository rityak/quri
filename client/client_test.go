package client

import (
	"context"
	"errors"
	mhttp "github.com/metacubex/http"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rityak/quri/auth"
	"github.com/rityak/quri/config"
	"github.com/rityak/quri/internal/testcert"
	"github.com/rityak/quri/route"
	"github.com/rityak/quri/session"
	"github.com/rityak/quri/transport"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

type blockedUDP struct {
	net.PacketConn
	closed *atomic.Int64
}

func (c *blockedUDP) WriteTo(p []byte, addr net.Addr) (int, error) { return len(p), nil }
func (c *blockedUDP) Close() error                                 { c.closed.Add(1); return c.PacketConn.Close() }

func TestBlockedUDPUsesH2AndRebindsAssociation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverTLS, clientTLS := testcert.TLS(t)
	listener, udp, err := transport.ListenSockets("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("client-secret-", 3)
	verifier, err := auth.New(map[string]string{"user": token})
	if err != nil {
		t.Fatal(err)
	}
	var configurations atomic.Int64
	handler, err := session.NewServer(func(ctx context.Context, principal string, request session.Request) (route.Route, error) {
		configurations.Add(1)
		return route.NewDirectRoute(route.DirectPolicy{Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	}, config.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := transport.NewServer(listener, udp, transport.ServerOptions{TLS: serverTLS, Auth: verifier, Website: mhttp.NotFoundHandler(), Handler: handler})
	if err != nil {
		t.Fatal(err)
	}
	serverCtx, stopServer := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- server.Serve(serverCtx) }()
	defer func() {
		stopServer()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	var closed atomic.Int64
	started := time.Now()
	m, err := Dial(ctx, Config{Address: listener.Addr().String(), Token: token, Configuration: session.Request{Namespace: "direct", Version: 1}, Transport: transport.ClientOptions{TLS: clientTLS, ListenPacket: func(ctx context.Context, remote netip.AddrPort) (net.PacketConn, error) {
		socket, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		return &blockedUDP{PacketConn: socket, closed: &closed}, nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTest(t, m) // Test owns the manager and its health worker.
	if m.Protocol() != "h2" || time.Since(started) > 2*time.Second {
		t.Fatalf("fallback protocol=%s duration=%s", m.Protocol(), time.Since(started))
	}
	if closed.Load() != 1 || configurations.Load() != 1 {
		t.Fatalf("loser sockets closed=%d configurations=%d", closed.Load(), configurations.Load())
	}
	target, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	targetDone := make(chan struct{})
	go func() {
		defer close(targetDone)
		var buf [2048]byte
		for {
			n, addr, err := target.ReadFrom(buf[:])
			if err != nil {
				return
			}
			if _, err := target.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	defer func() {
		if err := target.Close(); err != nil {
			t.Error(err)
		}
		<-targetDone
	}()
	packet, err := m.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := packet.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := packet.WriteTo([]byte("retained-association"), target.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		var buf [100]byte
		n, _, err := packet.ReadFrom(buf[:])
		if err != nil || string(buf[:n]) != "retained-association" {
			t.Fatalf("attempt %d: %q %v", attempt, buf[:n], err)
		}
		if attempt == 0 {
			m.mu.Lock()
			old := m.current
			changed := m.changed
			m.mu.Unlock()
			if err := old.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatal(err)
			}
			select {
			case <-changed:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
	}
	if configurations.Load() != 2 {
		t.Fatalf("reconnect configurations=%d", configurations.Load())
	}
	if err := packet.Close(); err != nil {
		t.Fatal(err)
	}
}

func closeTest(t testing.TB, c io.Closer) {
	t.Helper()
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Error(err)
	}
}
