package transport

import (
	"context"
	"io"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/rityak/quri/auth"
	"github.com/rityak/quri/config"
	"github.com/rityak/quri/internal/testcert"
)

func TestExternalWebsiteOverBothTransports(t *testing.T) {
	const missingPath = "/missing"
	requests := make(chan string, 16)
	backend := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		requests <- r.Method + " " + r.URL.RequestURI() + " " + r.Header.Get("Cookie")
		w.Header().Set("X-Website", "external")
		if r.URL.Path == missingPath {
			w.WriteHeader(stdhttp.StatusNotFound)
		}
		if _, err := io.WriteString(w, "external website"); err != nil {
			t.Error(err)
		}
	}))
	defer backend.Close()
	for _, protocol := range []string{"h3", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			website, err := NewWebsiteProxy(backend.URL, config.Config{})
			if err != nil {
				t.Fatal(err)
			}
			defer closeTest(t, website)
			serverTLS, clientTLS := testcert.TLS(t)
			tcp, udp, err := ListenSockets("127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			token := strings.Repeat("website-secret-", 3)
			verifier, err := auth.New(map[string]string{testPrincipal: token})
			if err != nil {
				t.Fatal(err)
			}
			server, err := NewServer(tcp, udp, ServerOptions{TLS: serverTLS, Auth: verifier, Website: website, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })})
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
			conn, err := Dial(ctx, tcp.Addr().String(), ClientOptions{TLS: clientTLS, Protocol: protocol})
			if err != nil {
				t.Fatal(err)
			}
			defer closeTest(t, conn)
			for _, path := range []string{"/", "/asset?v=2", missingPath} {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://localhost"+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				response, err := conn.RoundTrip(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				closeTest(t, response.Body)
				status := http.StatusOK
				if path == missingPath {
					status = http.StatusNotFound
				}
				if err != nil || response.StatusCode != status || response.Header.Get("X-Website") != "external" || string(body) != "external website" {
					t.Fatalf("website %s: status=%d body=%q error=%v", path, response.StatusCode, body, err)
				}
				if got := <-requests; got != "GET "+path+" " {
					t.Fatalf("backend request=%q", got)
				}
			}
			if err := conn.Authenticate(ctx, token); err != nil {
				t.Fatal(err)
			}
			if got := <-requests; got != "GET / " {
				t.Fatalf("authentication proof leaked to backend: %q", got)
			}
			if err := conn.Probe(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-requests:
				t.Fatalf("relay health check reached website: %q", got)
			default:
			}
		})
	}
}

func TestWebsiteURLValidation(t *testing.T) {
	for _, target := range []string{"", "file:///private", "http://", "http://user:secret@localhost/", "http://localhost/#fragment"} {
		if proxy, err := NewWebsiteProxy(target, config.Config{}); err == nil {
			closeTest(t, proxy)
			t.Fatalf("accepted website URL %q", target)
		}
	}
}
