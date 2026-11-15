package transport

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/rityak/quri/auth"
	"github.com/rityak/quri/internal/testcert"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func TestHTTPProofCannotAuthorizeAnotherConnection(t *testing.T) {
	for _, protocol := range []string{"h3", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			serverTLS, clientTLS := testcert.TLS(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			udp, err := net.ListenPacket("udp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			token := strings.Repeat("proof-secret-", 3)
			verifier, err := auth.New(map[string]string{testPrincipal: token})
			if err != nil {
				t.Fatal(err)
			}
			server, err := NewServer(listener, udp, ServerOptions{TLS: serverTLS, Auth: verifier, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			done := make(chan error, 1)
			go func() { done <- server.Serve(ctx) }()
			defer func() {
				cancel()
				if err := <-done; err != nil {
					t.Error(err)
				}
			}()
			first, err := Dial(ctx, listener.Addr().String(), ClientOptions{TLS: clientTLS, Protocol: protocol})
			if err != nil {
				t.Fatal(err)
			}
			defer closeTest(t, first) // Test owns both connections.
			second, err := Dial(ctx, listener.Addr().String(), ClientOptions{TLS: clientTLS, Protocol: protocol})
			if err != nil {
				t.Fatal(err)
			}
			defer closeTest(t, second)
			proof, err := auth.Proof(token, first.binding)
			if err != nil {
				t.Fatal(err)
			}
			for _, test := range []struct {
				conn   *Conn
				status int
			}{{first, 204}, {second, 200}} {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://localhost/", nil)
				if err != nil {
					t.Fatal(err)
				}
				req.AddCookie(&http.Cookie{Name: authCookie, Value: proof})
				response, err := test.conn.RoundTrip(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				if err := response.Body.Close(); err != nil {
					t.Fatal(err)
				}
				if err != nil || response.StatusCode != 200 || !strings.Contains(string(body), "<!doctype html>") {
					t.Fatalf("auth response: %d %q %v", response.StatusCode, body, err)
				}
				req, err = http.NewRequestWithContext(ctx, http.MethodPost, "https://localhost/api/session", nil)
				if err != nil {
					t.Fatal(err)
				}
				response, err = test.conn.RoundTrip(req)
				if err != nil {
					t.Fatal(err)
				}
				if err := response.Body.Close(); err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != test.status {
					t.Fatalf("replayed authorization: status=%d want=%d", response.StatusCode, test.status)
				}
			}
		})
	}
}
