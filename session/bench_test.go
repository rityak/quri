package session

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/rityak/quri/auth"
	"github.com/rityak/quri/config"
	"github.com/rityak/quri/internal/testcert"
	"github.com/rityak/quri/route"
	"github.com/rityak/quri/transport"
)

func BenchmarkUDPRoundTrip(b *testing.B) {
	for _, protocol := range []string{"h3", "h2"} {
		b.Run(protocol, func(b *testing.B) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			target, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			echoDone := make(chan struct{})
			go func() {
				defer close(echoDone)
				var buffer [2048]byte
				for {
					n, addr, err := target.ReadFrom(buffer[:])
					if err != nil {
						return
					}
					if _, err := target.WriteTo(buffer[:n], addr); err != nil {
						return
					}
				}
			}()
			defer func() {
				if err := target.Close(); err != nil {
					b.Error(err)
				}
				<-echoDone
			}()
			serverTLS, clientTLS := testcert.TLS(b)
			tcp, udp, err := transport.ListenSockets("127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			token := strings.Repeat("benchmark-secret-", 3)
			verifier, err := auth.New(map[string]string{"bench": token})
			if err != nil {
				b.Fatal(err)
			}
			handler, err := NewServer(func(context.Context, string, Request) (route.Route, error) {
				return route.NewDirectRoute(route.DirectPolicy{Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
			}, config.Config{}, nil)
			if err != nil {
				b.Fatal(err)
			}
			server, err := transport.NewServer(tcp, udp, transport.ServerOptions{TLS: serverTLS, Auth: verifier, Website: http.NotFoundHandler(), Handler: handler})
			if err != nil {
				b.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- server.Serve(ctx) }()
			defer func() {
				cancel()
				if err := <-done; err != nil {
					b.Error(err)
				}
				if err := handler.Close(); err != nil {
					b.Error(err)
				}
			}()
			connection, err := transport.Dial(ctx, tcp.Addr().String(), transport.ClientOptions{TLS: clientTLS, Protocol: protocol})
			if err != nil {
				b.Fatal(err)
			}
			session, err := New(ctx, connection, token, Request{Namespace: testNamespace, Version: 1}, config.Config{})
			if err != nil {
				b.Fatal(err)
			}
			defer func() {
				if err := session.Close(); err != nil {
					b.Error(err)
				}
			}()
			packet, err := session.ListenPacket(ctx)
			if err != nil {
				b.Fatal(err)
			}
			if err := packet.SetReadDeadline(time.Now().Add(time.Minute)); err != nil {
				b.Fatal(err)
			}
			address, err := route.UDPAddress(target.LocalAddr().String())
			if err != nil {
				b.Fatal(err)
			}
			var payload [512]byte
			var reply [512]byte
			exchange := func() {
				if _, err := packet.WriteTo(payload[:], address); err != nil {
					b.Fatal(err)
				}
				if n, _, err := packet.ReadFrom(reply[:]); err != nil || n != len(payload) {
					b.Fatalf("UDP reply: bytes=%d error=%v", n, err)
				}
			}
			for i := 0; i < 16; i++ {
				exchange()
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				exchange()
			}
			b.StopTimer()
		})
	}
}
