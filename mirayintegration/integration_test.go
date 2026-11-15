package mirayintegration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/rityak/quri"
	"github.com/rityak/quri/internal/testcert"
)

// directTunnel terminates real miray listeners without loading global config.
type directTunnel struct{ events chan<- string }

func (d directTunnel) event(message string) {
	select {
	case d.events <- message:
	default:
	}
}

func (directTunnel) HandleTCPConn(c net.Conn, m *C.Metadata) {
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d := net.Dialer{}
	target, err := d.DialContext(ctx, "tcp", m.RemoteAddress())
	if err == nil {
		quri.Relay(c, target)
	}
}
func (d directTunnel) HandleUDPPacket(p C.UDPPacket, m *C.Metadata) {
	address := m.RemoteAddress()
	d.event(fmt.Sprintf("inbound UDP bytes=%d destination=%s", len(p.Data()), address))
	go func() {
		defer p.Drop()
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		a, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return
		}
		if _, err = c.WriteTo(p.Data(), a); err != nil {
			d.event(err.Error())
			return
		}
		buffer := make([]byte, 65535)
		if n, source, err := c.ReadFrom(buffer); err == nil {
			written, err := p.WriteBack(buffer[:n], source)
			d.event(fmt.Sprintf("inbound reply bytes=%d/%d error=%v", written, n, err))
		} else {
			d.event(err.Error())
		}
	}()
}
func (directTunnel) NatTable() C.NatTable { return nil }

func startServer(t *testing.T, configure func(context.Context, quri.Principal, quri.Request) (quri.Route, error)) (string, quri.ClientConfig) {
	t.Helper()
	serverTLS, clientTLS := testcert.TLS(t)
	token := strings.Repeat("integration-secret-", 3)
	auth, err := quri.TokenAuthenticator(map[quri.Principal]string{"client": token})
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := quri.Listen(socket, quri.ServerConfig{TLS: serverTLS, Authenticate: auth, Configure: configure,
		Application: func(_ context.Context, _ quri.Principal, r quri.Request) ([]byte, error) { return r.Payload, nil }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Serve(ctx)
	t.Cleanup(func() {
		cancel()
		drain, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := srv.Shutdown(drain); err != nil {
			t.Error(err)
		}
	})
	return srv.Addr().String(), quri.ClientConfig{TLS: clientTLS, Token: token}
}

func TestMirayOutboundContract(t *testing.T) {
	const uuid = "ed482545-5182-437f-ad26-bff83ae53c36"
	certificate, key, fingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"hysteria2", "vless-xudp", "quri"} {
		t.Run(protocol, func(t *testing.T) {
			events := make(chan string, 128)
			t.Cleanup(func() {
				for len(events) > 0 {
					event := <-events
					if t.Failed() {
						t.Log(event)
					}
				}
			})
			var factory func(context.Context) (quri.Route, error)
			base := inbound.BaseOption{NameStr: "reference", Listen: "127.0.0.1", Port: "0"}
			switch protocol {
			case "hysteria2":
				in, err := inbound.NewHysteria2(&inbound.Hysteria2Option{BaseOption: base, Users: map[string]string{"client": uuid}, Certificate: certificate, PrivateKey: key})
				if err != nil {
					t.Fatal(err)
				}
				if err := in.Listen(directTunnel{events: events}); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { in.Close() })
				endpoint := netip.MustParseAddrPort(in.Address())
				factory = func(context.Context) (quri.Route, error) {
					p, err := outbound.NewHysteria2(outbound.Hysteria2Option{Name: "session", Server: endpoint.Addr().String(), Port: int(endpoint.Port()), Password: uuid, SNI: "localhost", Fingerprint: fingerprint})
					return &adapterRoute{proxy: p}, err
				}
			case "vless-xudp":
				in, err := inbound.NewVless(&inbound.VlessOption{BaseOption: base, Users: []inbound.VlessUser{{UUID: uuid}}, Certificate: certificate, PrivateKey: key})
				if err != nil {
					t.Fatal(err)
				}
				if err := in.Listen(directTunnel{events: events}); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { in.Close() })
				endpoint := netip.MustParseAddrPort(in.Address())
				factory = func(context.Context) (quri.Route, error) {
					p, err := outbound.NewVless(outbound.VlessOption{Name: "session", Server: endpoint.Addr().String(), Port: int(endpoint.Port()), UUID: uuid, TLS: true, Fingerprint: fingerprint, ServerName: "localhost", UDP: true, XUDP: true})
					return &adapterRoute{proxy: p}, err
				}
			case "quri":
				address, config := startServer(t, func(context.Context, quri.Principal, quri.Request) (quri.Route, error) {
					return quri.NewDirectRoute(quri.DirectPolicy{Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
				})
				config.Configuration = quri.Request{Namespace: "direct", Version: 1}
				factory = func(ctx context.Context) (quri.Route, error) {
					s, err := quri.Dial(ctx, address, config)
					return &nextRoute{session: s}, err
				}
			}
			// Only a session-local, allowlisted profile can be selected by the client.
			address, config := startServer(t, func(ctx context.Context, p quri.Principal, r quri.Request) (quri.Route, error) {
				var profile string
				if p != "client" || r.Namespace != "miray.outbound" || r.Version != 1 || json.Unmarshal(r.Payload, &profile) != nil || profile != protocol {
					return nil, quri.ErrDenied
				}
				return factory(ctx)
			})
			payload, _ := json.Marshal(protocol)
			config.Configuration = quri.Request{Namespace: "miray.outbound", Version: 1, Payload: payload}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			s, err := quri.Dial(ctx, address, config)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := s.Shutdown(ctx); err != nil {
					t.Error(err)
				}
				if err := s.Wait(ctx); err != nil {
					t.Error(err)
				}
			}()
			checkTraffic(t, ctx, s, protocol)
		})
	}
}

func checkTraffic(t *testing.T, ctx context.Context, s *quri.Session, protocol string) {
	checkClientTraffic(t, ctx, legacyTraffic{s}, protocol)
}

type trafficClient interface {
	DialContext(context.Context, string) (net.Conn, error)
	ListenPacket(context.Context) (net.PacketConn, error)
}

type legacyTraffic struct{ *quri.Session }

func (s legacyTraffic) DialContext(ctx context.Context, address string) (net.Conn, error) {
	return s.Session.DialContext(ctx, address)
}
func (s legacyTraffic) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	return s.Session.ListenPacket(ctx)
}

func checkClientTraffic(t *testing.T, ctx context.Context, s trafficClient, protocol string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	payload := bytes.Repeat([]byte("response-after-eof/"), 4096)
	served := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			served <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		b, err := io.ReadAll(c)
		if err == nil && string(b) != "request" {
			err = fmt.Errorf("wrong TCP request: %q", b)
		}
		if err == nil {
			_, err = c.Write(payload)
		}
		served <- err
	}()
	c, err := s.DialContext(ctx, l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(6 * time.Second))
	_, err = c.Write([]byte("request"))
	if err == nil {
		err = c.(interface{ CloseWrite() error }).CloseWrite()
	}
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	b, err := io.ReadAll(c)
	c.Close()
	if err != nil || !bytes.Equal(b, payload) {
		t.Fatalf("TCP half-close: bytes=%d/%d, err=%v", len(b), len(payload), err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	pc, err := s.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	for endpoint := 0; endpoint < 2; endpoint++ {
		target, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer target.Close()
		go func() {
			buffer := make([]byte, 65535)
			for {
				n, addr, err := target.ReadFrom(buffer)
				if err != nil {
					return
				}
				target.WriteTo(buffer[:n], addr)
			}
		}()
		sizes := []int{0, 1, 1200, 4096, 8192}
		if strings.HasPrefix(protocol, "http/") {
			sizes = []int{1, 512, 1150}
		}
		for _, size := range sizes {
			data := bytes.Repeat([]byte{byte(size + endpoint)}, size)
			pc.SetDeadline(time.Now().Add(3 * time.Second))
			// These limits belong to the selected miray transports, not quri.
			dropped := protocol == "hysteria2" && size > 4096 || protocol == "vless-xudp" && size == 0
			if dropped {
				pc.SetDeadline(time.Now().Add(200 * time.Millisecond))
			}
			if _, err := pc.WriteTo(data, target.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 65535)
			n, source, err := pc.ReadFrom(buffer)
			if dropped {
				if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
					t.Fatalf("transport limit changed: protocol=%s size=%d err=%v", protocol, size, err)
				}
				continue
			}
			if err != nil || source.String() != target.LocalAddr().String() || !bytes.Equal(buffer[:n], data) {
				t.Fatalf("UDP endpoint=%d size=%d bytes=%d source=%v err=%v", endpoint, size, n, source, err)
			}
		}
	}
	if legacy, ok := s.(legacyTraffic); ok {
		if reply, err := legacy.Message(ctx, quri.Request{Namespace: "status", Version: 1, Payload: []byte("alive")}); err != nil || string(reply) != "alive" {
			t.Fatal("service channel after traffic", string(reply), err)
		}
	}
}
