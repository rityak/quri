package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/rityak/quri/auth"
	"github.com/rityak/quri/internal/testcert"
)

const testPrincipal = "user"

func TestHTTPWebsiteAndAuthenticatedTunnel(t *testing.T) {
	for _, protocol := range []string{"h3", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			serverTLS, clientTLS := testcert.TLS(t)
			tcp, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			udp, err := net.ListenPacket("udp", tcp.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			token := strings.Repeat("secret-", 6)
			verifier, err := auth.New(map[string]string{testPrincipal: token})
			if err != nil {
				t.Fatal(err)
			}
			upload := make(chan string, 1)
			server, err := NewServer(tcp, udp, ServerOptions{TLS: serverTLS, Auth: verifier, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if PeerFromContext(r.Context()).Principal() != testPrincipal {
					t.Error("missing connection identity")
				}
				if r.Method != http.MethodConnect {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				tunnel, err := Accept(w, r, false, 1150)
				if err != nil {
					t.Error(err)
					return
				}
				defer closeTest(t, tunnel) // Handler owns this CONNECT stream.
				if _, err := io.WriteString(tunnel, "server-fin"); err != nil {
					t.Error(err)
					return
				}
				if err := tunnel.CloseWrite(); err != nil {
					t.Error(err)
					return
				}
				body, err := io.ReadAll(tunnel)
				if err != nil {
					t.Error(err)
					return
				}
				upload <- string(body)
			})})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			done := make(chan error, 1)
			go func() { done <- server.Serve(ctx) }()
			t.Cleanup(func() {
				cancel()
				if err := <-done; err != nil {
					t.Error(err)
				}
			})
			conn, err := Dial(ctx, tcp.Addr().String(), ClientOptions{TLS: clientTLS, Protocol: protocol})
			if err != nil {
				t.Fatal(err)
			}
			defer closeTest(t, conn) // Test owns this HTTP connection.
			for _, cookie := range []string{"", "session=invalid"} {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://localhost/", nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Cookie", cookie)
				response, err := conn.RoundTrip(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				if closeErr := response.Body.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
				if err != nil || response.StatusCode != 200 || !strings.Contains(string(body), "<!doctype html>") {
					t.Fatalf("website: %d %q %v", response.StatusCode, body, err)
				}
			}
			if err := conn.Authenticate(ctx, token); err != nil {
				t.Fatal(err)
			}
			stream, err := conn.Open(ctx, "target.example:443", false)
			if err != nil {
				t.Fatal(err)
			}
			defer closeTest(t, stream) // Test owns this CONNECT stream.
			body, err := io.ReadAll(stream)
			if err != nil || string(body) != "server-fin" {
				t.Fatalf("download: %q %v", body, err)
			}
			if _, err := io.WriteString(stream, "upload-after-fin"); err != nil {
				t.Fatal(err)
			}
			if err := stream.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-upload:
				if got != "upload-after-fin" {
					t.Fatal(got)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
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
