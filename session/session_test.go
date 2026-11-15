package session

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
	"github.com/rityak/quri/transport"
	"go.uber.org/goleak"
)

const testNamespace = "direct"

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func TestHTTPRelayTCPAndUDP(t *testing.T) {
	for _, protocol := range []string{"h3", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			targetTCP, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer closeTest(t, targetTCP) // Test owns the target listener.
			targetDone := make(chan error, 1)
			go func() {
				conn, err := targetTCP.Accept()
				if err != nil {
					targetDone <- err
					return
				}
				defer closeTest(t, conn) // Test owns the accepted target connection.
				body, err := io.ReadAll(conn)
				if err == nil {
					_, err = conn.Write(append([]byte("reply:"), body...))
				}
				targetDone <- err
			}()
			targetUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			udpDone := make(chan struct{})
			var datagrams atomic.Int64
			go func() {
				defer close(udpDone)
				var buffer [2048]byte
				for {
					n, addr, err := targetUDP.ReadFrom(buffer[:])
					if err != nil {
						return
					}
					datagrams.Add(1)
					if _, err := targetUDP.WriteTo(buffer[:n], addr); err != nil {
						return
					}
				}
			}()
			defer func() {
				if err := targetUDP.Close(); err != nil {
					t.Error(err)
				}
				<-udpDone
			}()
			serverTLS, clientTLS := testcert.TLS(t)
			listener, udp, err := transport.ListenSockets("127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			token := strings.Repeat("relay-secret-", 3)
			verifier, err := auth.New(map[string]string{"user": token})
			if err != nil {
				t.Fatal(err)
			}
			var configurations atomic.Int64
			handler, err := NewServer(func(ctx context.Context, principal string, request Request) (route.Route, error) {
				configurations.Add(1)
				if principal != "user" || request.Namespace != testNamespace || request.Version != 1 {
					return nil, route.ErrDenied
				}
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
			serverDone := make(chan error, 1)
			go func() { serverDone <- server.Serve(serverCtx) }()
			defer func() {
				stopServer()
				if err := <-serverDone; err != nil {
					t.Error(err)
				}
			}()
			connection, err := transport.Dial(ctx, listener.Addr().String(), transport.ClientOptions{TLS: clientTLS, Protocol: protocol})
			if err != nil {
				t.Fatal(err)
			}
			session, err := New(ctx, connection, token, Request{Namespace: testNamespace, Version: 1}, config.Config{})
			if err != nil {
				t.Fatal(err)
			}
			defer closeTest(t, session) // Test owns this client session.
			stream, err := session.DialContext(ctx, targetTCP.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(stream, "request"); err != nil {
				t.Fatal(err)
			}
			if err := stream.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(stream)
			if err != nil || string(body) != "reply:request" {
				t.Fatalf("TCP=%q %v", body, err)
			}
			if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
			if err := <-targetDone; err != nil {
				t.Fatal(err)
			}
			packet, err := session.ListenPacket(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := packet.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if n, err := packet.WriteTo(make([]byte, config.DefaultMaxDatagram+1), targetUDP.LocalAddr()); err != nil || n != config.DefaultMaxDatagram+1 {
				t.Fatalf("oversize=%d %v", n, err)
			}
			if _, err := packet.WriteTo([]byte("one-udp-packet"), targetUDP.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			var buffer [2048]byte
			n, addr, err := packet.ReadFrom(buffer[:])
			if err != nil || string(buffer[:n]) != "one-udp-packet" || addr.String() != targetUDP.LocalAddr().String() {
				t.Fatalf("UDP=%q %v %v", buffer[:n], addr, err)
			}
			if datagrams.Load() != 1 {
				t.Fatalf("target received %d packets, oversized packet was not dropped", datagrams.Load())
			}
			if configurations.Load() != 1 {
				t.Fatalf("route configured %d times", configurations.Load())
			}
			if err := packet.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatal(err)
			}
		})
	}
}

func closeTest(t testing.TB, c io.Closer) {
	t.Helper()
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Error(err)
	}
}
