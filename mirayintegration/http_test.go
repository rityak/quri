package mirayintegration

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	stdtls "crypto/tls"
	"encoding/base64"
	"encoding/pem"
	mhttp "github.com/metacubex/http"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/rityak/quri/auth"
	"github.com/rityak/quri/config"
	"github.com/rityak/quri/internal/testcert"
	"github.com/rityak/quri/route"
	"github.com/rityak/quri/session"
	"github.com/rityak/quri/transport"
)

func TestHTTPMirayFixedOutbound(t *testing.T) {
	const uuid = "ed482545-5182-437f-ad26-bff83ae53c36"
	certificate, key, fingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	for _, httpProtocol := range []string{"h3", "h2"} {
		for _, protocol := range []string{"vless", "vless-reality", "hysteria2"} {
			t.Run(httpProtocol+"/"+protocol, func(t *testing.T) {
				base := inbound.BaseOption{NameStr: "reference", Listen: "127.0.0.1", Port: "0"}
				var factory session.Factory
				events := make(chan string, 128)
				if protocol == "vless-reality" {
					pair, err := stdtls.X509KeyPair([]byte(certificate), []byte(key))
					if err != nil {
						t.Fatal(err)
					}
					origin := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { w.WriteHeader(stdhttp.StatusOK) }))
					origin.EnableHTTP2 = true
					origin.TLS = &stdtls.Config{Certificates: []stdtls.Certificate{pair}, MinVersion: stdtls.VersionTLS13}
					origin.StartTLS()
					defer origin.Close()
					private, err := ecdh.X25519().GenerateKey(rand.Reader)
					if err != nil {
						t.Fatal(err)
					}
					in, err := inbound.NewVless(&inbound.VlessOption{BaseOption: base, Users: []inbound.VlessUser{{UUID: uuid}}, RealityConfig: inbound.RealityConfig{Dest: strings.TrimPrefix(origin.URL, "https://"), PrivateKey: base64.RawURLEncoding.EncodeToString(private.Bytes()), ServerNames: []string{"localhost"}, ShortID: []string{"01"}}})
					if err != nil {
						t.Fatal(err)
					}
					if err := in.Listen(directTunnel{events: events}); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { in.Close() })
					link := "vless://" + uuid + "@" + in.Address() + "?security=reality&type=tcp&sni=localhost&fp=chrome&sid=01&pbk=" + base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
					factory = func(ctx context.Context, principal string, request session.Request) (route.Route, error) {
						return NewOutbound(link)
					}
				} else if protocol == "vless" {
					in, err := inbound.NewVless(&inbound.VlessOption{BaseOption: base, Users: []inbound.VlessUser{{UUID: uuid}}, Certificate: certificate, PrivateKey: key})
					if err != nil {
						t.Fatal(err)
					}
					if err := in.Listen(directTunnel{events: events}); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { in.Close() })
					endpoint := netip.MustParseAddrPort(in.Address())
					factory = func(ctx context.Context, principal string, request session.Request) (route.Route, error) {
						proxy, err := outbound.NewVless(outbound.VlessOption{Name: "session", Server: endpoint.Addr().String(), Port: int(endpoint.Port()), UUID: uuid, TLS: true, Fingerprint: fingerprint, ServerName: "localhost", UDP: true, XUDP: true})
						if err != nil {
							return nil, err
						}
						return NewAdapter(proxy)
					}
				} else {
					in, err := inbound.NewHysteria2(&inbound.Hysteria2Option{BaseOption: base, Users: map[string]string{"client": uuid}, Certificate: certificate, PrivateKey: key})
					if err != nil {
						t.Fatal(err)
					}
					if err := in.Listen(directTunnel{events: events}); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { in.Close() })
					endpoint := netip.MustParseAddrPort(in.Address())
					factory = func(ctx context.Context, principal string, request session.Request) (route.Route, error) {
						proxy, err := outbound.NewHysteria2(outbound.Hysteria2Option{Name: "session", Server: endpoint.Addr().String(), Port: int(endpoint.Port()), Password: uuid, SNI: "localhost", Fingerprint: fingerprint})
						if err != nil {
							return nil, err
						}
						return NewAdapter(proxy)
					}
				}
				serverTLS, clientTLS := testcert.TLS(t)
				listener, udp, err := transport.ListenSockets("127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				token := strings.Repeat("http-miray-secret-", 3)
				verifier, err := auth.New(map[string]string{"user": token})
				if err != nil {
					t.Fatal(err)
				}
				handler, err := session.NewServer(factory, config.Config{}, nil)
				if err != nil {
					t.Fatal(err)
				}
				server, err := transport.NewServer(listener, udp, transport.ServerOptions{TLS: serverTLS, Auth: verifier, Website: mhttp.NotFoundHandler(), Handler: handler})
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				done := make(chan error, 1)
				go func() { done <- server.Serve(ctx) }()
				defer func() {
					cancel()
					if err := <-done; err != nil {
						t.Error(err)
					}
				}()
				host, service, err := net.SplitHostPort(listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				port, err := strconv.Atoi(service)
				if err != nil {
					t.Fatal(err)
				}
				proxy, err := adapter.ParseProxy(map[string]any{"type": "quri", "name": "relay-client", "server": host, "port": port, "token": token, "sni": clientTLS.ServerName, "transports": []string{httpProtocol}, "ca": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverTLS.Certificates[0].Certificate[0]}))})
				if err != nil {
					t.Fatal(err)
				}
				manager, err := NewAdapter(proxy)
				if err != nil {
					t.Fatal(err)
				}
				defer manager.Close() // Test owns the manager and every session-local outbound.
				checkClientTraffic(t, ctx, manager, "http/"+protocol)
			})
		}
	}
}

func TestOutboundShareLink(t *testing.T) {
	const uuid = "ed482545-5182-437f-ad26-bff83ae53c36"
	for _, link := range []string{"vless://" + uuid + "@relay.example:443?security=tls&type=tcp", "hy2://password@relay.example:443?sni=relay.example"} {
		adapter, err := NewOutbound(link)
		if err != nil {
			t.Fatal(err)
		}
		if err := adapter.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for _, link := range []string{"vless://secret@relay.example:443?security=reality", "hy2://secret@relay.example:443?insecure=1", "vless://secret@relay.example:443?security=tls&type=ws"} {
		if _, err := NewOutbound(link); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("unsafe link error: %v", err)
		}
	}
}
