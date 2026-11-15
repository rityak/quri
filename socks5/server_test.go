package socks5

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rityak/quri"
	"github.com/rityak/quri/internal/testcert"
	"golang.org/x/net/proxy"
)

func TestSOCKS5EndToEnd(t *testing.T) {
	serverTLS, clientTLS := testcert.TLS(t)
	token := strings.Repeat("test-only-secret", 3)
	auth, err := quri.TokenAuthenticator(map[quri.Principal]string{"test": token})
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := quri.Listen(socket, quri.ServerConfig{TLS: serverTLS, Authenticate: auth, Configure: func(ctx context.Context, p quri.Principal, r quri.Request) (quri.Route, error) {
		return quri.NewDirectRoute(quri.DirectPolicy{Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx) }()
	defer func() {
		shutdown, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		server.Shutdown(shutdown)
		<-served
	}()
	session, err := quri.Dial(ctx, server.Addr().String(), quri.ClientConfig{TLS: clientTLS, Token: token, Configuration: quri.Request{Namespace: "direct", Version: 1, Payload: []byte("{}")}})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socksCtx, stopSocks := context.WithCancel(ctx)
	socksDone := make(chan error, 1)
	go func() { socksDone <- Serve(socksCtx, local, session) }()
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
	defer target.Close()
	go func() {
		c, err := target.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		data, err := io.ReadAll(c)
		if err == nil {
			c.Write(append([]byte("reply:"), data...))
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
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte("tcp"))
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
	defer udp.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			udp.WriteTo(b[:n], a)
		}
	}()
	control, err := net.Dial("tcp", local.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	control.SetDeadline(time.Now().Add(3 * time.Second))
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
	defer client.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	endpoint := udp.LocalAddr().(*net.UDPAddr)
	request := []byte{0, 0, 0, 1, 127, 0, 0, 1, byte(endpoint.Port >> 8), byte(endpoint.Port)}
	payload := bytes.Repeat([]byte("udp"), 3000)
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
	local.Close()
	if _, err = client.WriteTo(request, relayAddr); err != nil {
		t.Fatal(err)
	}
	if n, _, err = client.ReadFrom(buffer); err != nil || !bytes.Equal(buffer[:n], request) {
		t.Fatal("listener close aborted existing association", err)
	}
	control.Close()
	client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
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
	f.Fuzz(func(t *testing.T, b []byte) { readAddress(bytes.NewReader(b)) })
}
