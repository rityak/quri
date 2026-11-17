package interop_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	stdtls "crypto/tls"
	"encoding/base64"
	mhttp "github.com/metacubex/http"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rityak/quri/auth"
	"github.com/rityak/quri/client"
	"github.com/rityak/quri/config"
	"github.com/rityak/quri/internal/testcert"
	"github.com/rityak/quri/route"
	"github.com/rityak/quri/session"
	"github.com/rityak/quri/transport"
)

func independentProof(t *testing.T, token string, state stdtls.ConnectionState) string {
	t.Helper()
	binding, err := state.ExportKeyingMaterial("EXPORTER-quri-auth", nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte(token))
	if _, err := mac.Write(binding); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestHTTPClientAgainstStockHTTP3(t *testing.T) {
	serverTLS, clientTLS := testcert.TLS(t)
	certificate := serverTLS.Certificates[0]
	listener, err := quic.ListenAddr("127.0.0.1:0", &stdtls.Config{MinVersion: stdtls.VersionTLS13, NextProtos: []string{"h3"}, Certificates: []stdtls.Certificate{{Certificate: certificate.Certificate, PrivateKey: certificate.PrivateKey}}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("stock-http-secret-", 3)
	type key struct{}
	type peer struct {
		proof      string
		authorized atomic.Bool
	}
	stock := &http3.Server{EnableDatagrams: true}
	stock.ConnContext = func(ctx context.Context, conn *quic.Conn) context.Context {
		return context.WithValue(ctx, key{}, &peer{proof: independentProof(t, token, conn.ConnectionState().TLS)})
	}
	stock.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.Context().Value(key{}).(*peer)
		if r.Method == http.MethodGet {
			if cookie, err := r.Cookie("session"); err == nil && hmac.Equal([]byte(cookie.Value), []byte(p.proof)) {
				p.authorized.Store(true)
			}
			_, _ = io.WriteString(w, "website") // The client may disconnect after receiving the page.
			return
		}
		if !p.authorized.Load() {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost || r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Proto == "connect-udp" {
			if r.URL.Path != "/.well-known/masque/udp/example.org/53/" || r.Header.Get("Capsule-Protocol") != "?1" {
				t.Error("invalid RFC 9298 request")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Capsule-Protocol", "?1")
		}
		w.WriteHeader(http.StatusOK)
		stream := w.(http3.HTTPStreamer).HTTPStream()
		if r.Proto == "connect-udp" {
			for {
				data, err := stream.ReceiveDatagram(r.Context())
				if err != nil {
					return
				}
				if len(data) == 0 || data[0] != 0 {
					t.Error("missing context zero")
					return
				}
				if err := stream.SendDatagram(data); err != nil {
					return
				}
			}
		}
		body, err := io.ReadAll(stream)
		if err == nil {
			_, err = stream.Write(append([]byte("stock/"), body...))
		}
		if err != nil {
			t.Error(err)
		}
		if err := stream.Close(); err != nil {
			t.Error(err)
		}
	})
	done := make(chan error, 1)
	go func() { done <- stock.ServeListener(listener) }()
	defer func() {
		if err := stock.Close(); err != nil {
			t.Error(err)
		}
		<-done
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	manager, err := client.Dial(ctx, client.Config{Address: listener.Addr().String(), Token: token, Transports: []string{"h3"}, Configuration: session.Request{Namespace: "interop", Version: 1}, Transport: transport.ClientOptions{TLS: clientTLS}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close() // Test owns all client resources.
	stream, err := manager.DialContext(ctx, "target.example:443")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Migrate(ctx); err != nil {
		t.Fatalf("stock TCP migration: %v", err)
	}
	if _, err := io.WriteString(stream, "upload"); err != nil {
		t.Fatal(err)
	}
	if err := stream.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(stream)
	if err != nil || string(body) != "stock/upload" {
		t.Fatalf("stock TCP: %q %v", body, err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	packet, err := manager.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close() // Manager also closes associations on shutdown.
	addr, err := route.UDPAddress("example.org:53")
	if err != nil {
		t.Fatal(err)
	}
	if err := packet.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := packet.WriteTo([]byte("one-datagram"), addr); err != nil {
		t.Fatal(err)
	}
	var buf [128]byte
	n, _, err := packet.ReadFrom(buf[:])
	if err != nil || string(buf[:n]) != "one-datagram" {
		t.Fatalf("stock UDP: %q %v", buf[:n], err)
	}
	if err := manager.Migrate(ctx); err != nil {
		t.Fatalf("stock UDP migration: %v", err)
	}
	if _, err := packet.WriteTo([]byte("after-migration"), addr); err != nil {
		t.Fatal(err)
	}
	n, _, err = packet.ReadFrom(buf[:])
	if err != nil || string(buf[:n]) != "after-migration" {
		t.Fatalf("stock migrated UDP: %q %v", buf[:n], err)
	}
}

func TestStockHTTP3ClientAgainstRelay(t *testing.T) {
	serverTLS, clientTLS := testcert.TLS(t)
	tcp, udp, err := transport.ListenSockets("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("stock-client-secret-", 3)
	verifier, err := auth.New(map[string]string{"stock": token})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := session.NewServer(func(ctx context.Context, principal string, request session.Request) (route.Route, error) {
		return route.NewDirectRoute(route.DirectPolicy{Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	}, config.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := transport.NewServer(tcp, udp, transport.ServerOptions{TLS: serverTLS, Auth: verifier, Website: mhttp.NotFoundHandler(), Handler: handler})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	conn, err := quic.DialAddr(ctx, tcp.Addr().String(), &stdtls.Config{MinVersion: stdtls.VersionTLS13, ServerName: clientTLS.ServerName, RootCAs: clientTLS.RootCAs, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "") // The stock client owns this connection.
	stock := (&http3.Transport{EnableDatagrams: true}).NewClientConn(conn)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://localhost/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(&http.Cookie{Name: "session", Value: independentProof(t, token, conn.ConnectionState().TLS)})
	response, err := stock.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	request, err = http.NewRequestWithContext(ctx, http.MethodPost, "https://localhost/api/session", bytes.NewBufferString(`{"namespace":"direct","version":1}`))
	if err != nil {
		t.Fatal(err)
	}
	response, err = stock.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("configuration status=%d", response.StatusCode)
	}
	target, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	targetDone := make(chan error, 1)
	go func() {
		var b [128]byte
		n, addr, err := target.ReadFrom(b[:])
		if err == nil {
			_, err = target.WriteTo(b[:n], addr)
		}
		targetDone <- err
	}()
	defer target.Close() // Test owns the UDP echo socket.
	_, port, err := net.SplitHostPort(target.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	stream, err := stock.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	request, err = http.NewRequestWithContext(ctx, http.MethodConnect, "https://localhost/.well-known/masque/udp/127.0.0.1/"+port+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Proto = "connect-udp"
	request.Header.Set("Capsule-Protocol", "?1")
	if err := stream.SendRequestHeader(request); err != nil {
		t.Fatal(err)
	}
	response, err = stream.ReadResponse()
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("CONNECT-UDP response=%v error=%v", response, err)
	}
	if err := stream.SendDatagram([]byte{0, 1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	data, err := stream.ReceiveDatagram(ctx)
	if err != nil || !bytes.Equal(data, []byte{0, 1, 2, 3}) {
		t.Fatalf("stock client UDP=%x %v", data, err)
	}
	if err := <-targetDone; err != nil {
		t.Fatal(err)
	}
}
