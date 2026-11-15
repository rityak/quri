package quri

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/tls"
	"github.com/rityak/quri/internal/testcert"
)

func testPair(t testing.TB, sockets ...net.PacketConn) (*Session, *Server) {
	return testPairOn(t, "udp", "127.0.0.1:0", sockets...)
}

func testPairOn(t testing.TB, network, address string, sockets ...net.PacketConn) (*Session, *Server) {
	t.Helper()
	serverTLS, clientTLS := testcert.TLS(t)
	token := strings.Repeat("test-secret-", 4)
	auth, err := TokenAuthenticator(map[Principal]string{"test": token})
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket(network, address)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := Listen(pc, ServerConfig{TLS: serverTLS, Authenticate: auth, Configure: func(ctx context.Context, p Principal, r Request) (Route, error) {
		if p != "test" || r.Namespace != "direct" || r.Version != 1 || string(r.Payload) != "{}" {
			return nil, ErrDenied
		}
		return NewDirectRoute(DirectPolicy{Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}})
	}, Application: func(ctx context.Context, p Principal, r Request) ([]byte, error) { return r.Payload, nil }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		shutdown, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		select {
		case <-served:
		case <-shutdown.Done():
			t.Error("server did not stop")
		}
		srv.Shutdown(shutdown)
	})
	dial, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	var socket net.PacketConn
	if len(sockets) > 0 {
		socket = sockets[0]
	}
	session, err := Dial(dial, srv.Addr().String(), ClientConfig{Application: func(ctx context.Context, r Request) ([]byte, error) { return r.Payload, nil }, PacketConn: socket, TLS: clientTLS, Token: token, Configuration: Request{Namespace: "direct", Version: 1, Payload: []byte("{}")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		session.Close()
		wait, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := session.Wait(wait); err != nil {
			t.Error(err)
		}
	})
	return session, srv
}

func TestTCPHalfCloseAndControl(t *testing.T) {
	s, _ := testPair(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	payload := bytes.Repeat([]byte("response-after-eof"), 16384)
	done := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		b, err := io.ReadAll(c)
		if err == nil && string(b) != "request" {
			err = ErrProtocol
		}
		if err == nil {
			err = writeAll(c, payload)
		}
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := s.DialContext(ctx, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	stream.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = stream.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err = stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("response: %d bytes, expected %d", len(got), len(payload))
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	reply, err := s.Message(ctx, Request{Namespace: "test", Version: 1, Payload: []byte("service")})
	if err != nil || string(reply) != "service" {
		t.Fatalf("control: %q %v", reply, err)
	}
	if err = s.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestUDPEndToEnd(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) { testUDPEndToEnd(t, "udp4", "127.0.0.1:0", 65507) })
	t.Run("IPv6", func(t *testing.T) { testUDPEndToEnd(t, "udp6", "[::1]:0", 65527) })
}

func testUDPEndToEnd(t *testing.T, network, address string, maximum int) {
	s, _ := testPairOn(t, network, address)
	target, err := net.ListenPacket(network, address)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			n, addr, err := target.ReadFrom(b)
			if err != nil {
				return
			}
			target.WriteTo(b[:n], addr)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := s.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, size := range []int{0, 1, 1024, 8192, maximum} {
		payload := bytes.Repeat([]byte{byte(size + 3)}, size)
		p.SetDeadline(time.Now().Add(2 * time.Second))
		if n, err := p.WriteTo(payload, target.LocalAddr()); err != nil || n != size {
			t.Fatalf("write %d: %d %v", size, n, err)
		}
		b := make([]byte, 65535)
		n, addr, err := p.ReadFrom(b)
		if err != nil {
			t.Fatalf("read %d: %v; stats=%+v", size, err, s.Statistics())
		}
		if addr.String() != target.LocalAddr().String() || !bytes.Equal(payload, b[:n]) {
			t.Fatalf("datagram %d: %d from %s", size, n, addr)
		}
	}
	if _, err := p.WriteTo([]byte("short"), target.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if _, _, err = p.ReadFrom(make([]byte, 1)); err != io.ErrShortBuffer {
		t.Fatalf("short buffer: %v", err)
	}
	p.SetReadDeadline(time.Now().Add(time.Millisecond))
	if _, _, err = p.ReadFrom(make([]byte, 1)); err == nil {
		t.Fatal("missing deadline")
	}
}

func TestConfigurationAndDestinationsDenied(t *testing.T) {
	s, srv := testPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := s.request(ctx, configureKind, Request{Namespace: "direct", Version: 1, Payload: []byte("{}")}); err == nil {
		t.Fatal("configuration mutated")
	}
	if _, err := s.DialContext(ctx, "192.0.2.1:80"); err == nil {
		t.Fatal("destination outside allowlist accepted")
	}
	_, clientTLS := testcert.TLS(t)
	if _, err := Dial(ctx, srv.Addr().String(), ClientConfig{TLS: clientTLS, Token: strings.Repeat("x", 32), Configuration: Request{Namespace: "direct", Version: 1}}); err == nil {
		t.Fatal("untrusted server accepted")
	}
}

func TestAuthenticationAndInitialConfigurationRefusal(t *testing.T) {
	_, server := testPair(t)
	pool := x509.NewCertPool()
	certificate, err := x509.ParseCertificate(server.cfg.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(certificate)
	tc := &tls.Config{RootCAs: pool, ServerName: "localhost"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cases := []ClientConfig{
		{TLS: tc, Token: strings.Repeat("wrong", 8), Configuration: Request{Namespace: "direct", Version: 1, Payload: []byte("{}")}},
		{TLS: tc, Token: strings.Repeat("test-secret-", 4), Configuration: Request{Namespace: "forbidden", Version: 1, Payload: []byte("{}")}},
	}
	for _, cfg := range cases {
		session, err := Dial(ctx, server.Addr().String(), cfg)
		if session != nil {
			session.Close()
		}
		if err == nil {
			t.Fatal("unauthorized session accepted")
		}
	}
}
