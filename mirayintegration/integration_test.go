package mirayintegration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/rityak/quri/route"
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
		route.Relay(c, target)
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

type trafficClient interface {
	DialContext(context.Context, string) (net.Conn, error)
	ListenPacket(context.Context) (net.PacketConn, error)
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
		sizes := []int{1, 512, 1150}
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
}
