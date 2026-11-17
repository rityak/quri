package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/rityak/quri/auth"
	"github.com/rityak/quri/internal/testcert"
)

type migrationSocket struct {
	net.PacketConn
	drop   bool
	closed atomic.Bool
}

func (s *migrationSocket) WriteTo(data []byte, address net.Addr) (int, error) {
	if s.drop {
		return len(data), nil
	}
	return s.PacketConn.WriteTo(data, address)
}

func (s *migrationSocket) Close() error {
	s.closed.Store(true)
	return s.PacketConn.Close()
}

func TestMigrationPreservesTunnelsAndReleasesSockets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	serverTLS, clientTLS := testcert.TLS(t)
	tcp, udp, err := ListenSockets("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("migration-secret-", 3)
	verifier, err := auth.New(map[string]string{testPrincipal: token})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(tcp, udp, ServerOptions{TLS: serverTLS, Auth: verifier, Website: testWebsite(), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, targetErr := UDPTarget(r)
		isUDP := targetErr == nil
		tunnel, err := Accept(w, r, isUDP, 1150)
		if err != nil {
			t.Error(err)
			return
		}
		defer closeTest(t, tunnel)
		if !isUDP {
			_, _ = io.Copy(tunnel, tunnel) //nolint:errcheck // Closing a test tunnel ends the echo loop.
			return
		}
		var buffer [1150]byte
		for {
			n, err := tunnel.ReceiveDatagram(r.Context(), buffer[:])
			if err != nil {
				return
			}
			if err := tunnel.SendDatagram(r.Context(), buffer[:n]); err != nil {
				return
			}
		}
	})})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	var sockets []*migrationSocket
	blackhole := false
	candidateStarted := make(chan struct{}, 1)
	conn, err := Dial(ctx, tcp.Addr().String(), ClientOptions{TLS: clientTLS, Protocol: "h3", ListenPacket: func(context.Context, netip.AddrPort) (net.PacketConn, error) {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		socket := &migrationSocket{PacketConn: pc, drop: blackhole}
		sockets = append(sockets, socket)
		if blackhole {
			candidateStarted <- struct{}{}
		}
		return socket, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTest(t, conn)
	if err := conn.Authenticate(ctx, token); err != nil {
		t.Fatal(err)
	}
	stream, err := conn.Open(ctx, "target.example:443", false)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTest(t, stream)
	datagrams, err := conn.Open(ctx, "target.example:53", true)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTest(t, datagrams)
	exchange := func() {
		t.Helper()
		if _, err := stream.Write([]byte{42}); err != nil {
			t.Fatal(err)
		}
		var received [1]byte
		if _, err := io.ReadFull(stream, received[:]); err != nil || received[0] != 42 {
			t.Fatalf("TCP exchange after migration: %v %v", received, err)
		}
		if err := datagrams.SendDatagram(ctx, []byte{43}); err != nil {
			t.Fatal(err)
		}
		if n, err := datagrams.ReceiveDatagram(ctx, received[:]); err != nil || n != 1 || received[0] != 43 {
			t.Fatalf("UDP exchange after migration: %d %v %v", n, received, err)
		}
	}
	exchange()
	for i := range 3 {
		if err := conn.Migrate(ctx); err != nil {
			t.Fatalf("migration %d: %v", i, err)
		}
		exchange()
		for _, socket := range sockets[:len(sockets)-1] {
			if !socket.closed.Load() {
				t.Fatal("migration retained an inactive socket")
			}
		}
	}
	blackhole = true
	probeCtx, stop := context.WithTimeout(ctx, 200*time.Millisecond)
	defer stop()
	var workers sync.WaitGroup
	defer workers.Wait()
	failed, queued := make(chan error, 1), make(chan error, 1)
	workers.Add(1)
	go func() { defer workers.Done(); failed <- conn.Migrate(probeCtx) }()
	select {
	case <-candidateStarted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	canceledCtx, canceled := context.WithCancel(ctx)
	canceled()
	workers.Add(1)
	go func() { defer workers.Done(); queued <- conn.Migrate(canceledCtx) }()
	waitCtx, endWait := context.WithTimeout(ctx, 100*time.Millisecond)
	defer endWait()
	select {
	case err := <-queued:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("queued migration ignored cancellation: %v", err)
		}
	case <-waitCtx.Done():
		t.Fatal("canceled migration waited for the active path operation")
	}
	err = <-failed
	stop()
	if !errors.Is(err, context.DeadlineExceeded) || !sockets[len(sockets)-1].closed.Load() {
		t.Fatalf("failed candidate cleanup: %v", err)
	}
	exchange()
}
