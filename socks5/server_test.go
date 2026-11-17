package socks5

import (
	"bytes"
	"context"
	"errors"
	mhttp "github.com/metacubex/http"
	"go.uber.org/goleak"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rityak/quri/auth"
	"github.com/rityak/quri/client"
	"github.com/rityak/quri/config"
	"github.com/rityak/quri/internal/testcert"
	"github.com/rityak/quri/route"
	"github.com/rityak/quri/session"
	"github.com/rityak/quri/transport"
	"golang.org/x/net/proxy"
)

func TestSOCKS5EndToEnd(t *testing.T) {
	serverTLS, clientTLS := testcert.TLS(t)
	token := strings.Repeat("test-only-secret", 3)
	verifier, err := auth.New(map[string]string{"test": token})
	if err != nil {
		t.Fatal(err)
	}
	listener, socket, err := transport.ListenSockets("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := session.NewServer(func(ctx context.Context, principal string, request session.Request) (route.Route, error) {
		return route.NewDirectRoute(route.DirectPolicy{Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	}, config.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := transport.NewServer(listener, socket, transport.ServerOptions{TLS: serverTLS, Auth: verifier, Website: mhttp.NotFoundHandler(), Handler: handler})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx) }()
	defer func() {
		cancel()
		if err := <-served; err != nil {
			t.Error(err)
		}
	}()
	manager, err := client.Dial(ctx, client.Config{Address: listener.Addr().String(), Token: token, Transport: transport.ClientOptions{TLS: clientTLS}, Configuration: session.Request{Namespace: "direct", Version: 1}})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTest(t, manager) // Test owns the client manager.
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socksCtx, stopSocks := context.WithCancel(ctx)
	socksDone := make(chan error, 1)
	go func() { socksDone <- Serve(socksCtx, local, manager) }()
	defer func() {
		stopSocks()
		if err := <-socksDone; err != nil {
			t.Error(err)
		}
	}()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer closeTest(t, target)
	go func() {
		c, err := target.Accept()
		if err != nil {
			return
		}
		defer closeTest(t, c)
		data, err := io.ReadAll(c)
		if err == nil {
			if _, err := c.Write(append([]byte("reply:"), data...)); err != nil {
				t.Error(err)
			}
		}
	}()
	dialer, err := proxy.SOCKS5("tcp", local.Addr().String(), nil, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c, err := dialer.Dial("tcp", target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer closeTest(t, c)
	if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Error(err)
	}
	if _, err := c.Write([]byte("tcp")); err != nil {
		t.Error(err)
	}
	if err = c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(c)
	if err != nil || string(data) != "reply:tcp" {
		t.Fatalf("TCP: %q %v", data, err)
	}

	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer closeTest(t, udp)
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			if _, err := udp.WriteTo(b[:n], a); err != nil {
				t.Error(err)
			}
		}
	}()
	control, err := net.Dial("tcp", local.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer closeTest(t, control)
	if err := control.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Error(err)
	}
	if _, err = control.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err = io.ReadFull(control, method[:]); err != nil || method != [2]byte{5, 0} {
		t.Fatal(method, err)
	}
	// This request is a literal RFC 1928 UDP ASSOCIATE for an unspecified endpoint.
	if _, err = control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	var header [3]byte
	if _, err = io.ReadFull(control, header[:]); err != nil || header != [3]byte{5, 0, 0} {
		t.Fatal(header, err)
	}
	relay, err := readAddress(control)
	if err != nil {
		t.Fatal(err)
	}
	relayAddr, err := net.ResolveUDPAddr("udp", relay)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer closeTest(t, client)
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Error(err)
	}
	endpoint := udp.LocalAddr().(*net.UDPAddr)
	request := []byte{0, 0, 0, 1, 127, 0, 0, 1, byte((endpoint.Port >> 8) & 0xff), byte(endpoint.Port & 0xff)}
	payload := bytes.Repeat([]byte("udp"), 300)
	request = append(request, payload...)
	if _, err = client.WriteTo(request, relayAddr); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 65535)
	n, _, err := client.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer[:n], request) {
		t.Fatalf("UDP response mismatch: %d bytes", n)
	}
	// Stopping acceptance must preserve existing associations until their owner closes them.
	closeTest(t, local)
	if _, err = client.WriteTo(request, relayAddr); err != nil {
		t.Fatal(err)
	}
	if n, _, err = client.ReadFrom(buffer); err != nil || !bytes.Equal(buffer[:n], request) {
		t.Fatal("listener close aborted existing association", err)
	}
	closeTest(t, control)
	if err := client.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Error(err)
	}
	if _, err = client.WriteTo(request, relayAddr); err != nil {
		t.Fatal(err)
	}
	if _, _, err = client.ReadFrom(buffer); err == nil {
		t.Fatal("closed UDP association still forwarded")
	}
}

func FuzzSOCKSAddress(f *testing.F) {
	f.Add([]byte{1, 127, 0, 0, 1, 0, 80})
	f.Add([]byte{3, 1, 'x', 0, 53})
	f.Add([]byte{4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = readAddress(bytes.NewReader(b)) }) //nolint:errcheck // Malformed fuzz inputs are expected to return errors.
}

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }
func closeTest(t testing.TB, c io.Closer) {
	t.Helper()
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Error(err)
	}
}
