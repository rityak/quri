package interop_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rityak/quri"
	"github.com/rityak/quri/internal/testcert"
)

// This client uses stock upstream QUIC and independently encodes the quri wire
// format. The production module never imports the upstream QUIC module.
func TestStockQUICClient(t *testing.T) {
	serverTLS, clientTLS := testcert.TLS(t)
	token := strings.Repeat("independent-test", 3)
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go server.Serve(ctx)
	defer func() {
		drain, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		server.Shutdown(drain)
	}()
	c, err := quic.DialAddr(ctx, server.Addr().String(), &tls.Config{RootCAs: clientTLS.RootCAs, ServerName: "localhost", NextProtos: []string{"quri/1"}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseWithError(0, "test complete")
	control, err := c.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	control.SetDeadline(time.Now().Add(5 * time.Second))
	if err = put(control, []byte(`{"version":1,"token":"`+token+`","udp":true}`)); err != nil {
		t.Fatal(err)
	}
	checkResponse(t, control)
	cfg := []byte(`{"namespace":"direct","version":1,"payload":"e30="}`)
	var h [13]byte
	h[0] = 1
	binary.BigEndian.PutUint64(h[1:9], 1)
	binary.BigEndian.PutUint32(h[9:], uint32(len(cfg)))
	if _, err = control.Write(append(h[:], cfg...)); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(control, h[:]); err != nil {
		t.Fatal(err)
	}
	if h[0] != 0x81 || binary.BigEndian.Uint64(h[1:9]) != 1 {
		t.Fatal("configuration response header")
	}
	body := make([]byte, binary.BigEndian.Uint32(h[9:]))
	if _, err = io.ReadFull(control, body); err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"handle":1}` {
		t.Fatalf("configuration: %s", body)
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		target, err := tcp.Accept()
		if err != nil {
			return
		}
		defer target.Close()
		b, _ := io.ReadAll(target)
		target.Write(append([]byte("reply:"), b...))
	}()
	st, err := c.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st.SetDeadline(time.Now().Add(5 * time.Second))
	raw, _ := json.Marshal(map[string]any{"kind": "tcp", "handle": 1, "address": tcp.Addr().String()})
	if err = put(st, raw); err != nil {
		t.Fatal(err)
	}
	checkResponse(t, st)
	st.Write([]byte("stock"))
	st.Close()
	answer, err := io.ReadAll(st)
	if err != nil || string(answer) != "reply:stock" {
		t.Fatal(string(answer), err)
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 1024)
		n, a, err := udp.ReadFrom(b)
		if err == nil {
			udp.WriteTo(b[:n], a)
		}
	}()
	flow, err := c.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	flow.SetDeadline(time.Now().Add(5 * time.Second))
	if err = put(flow, []byte(`{"kind":"udp","handle":1}`)); err != nil {
		t.Fatal(err)
	}
	checkResponse(t, flow)
	address := udp.LocalAddr().String()
	packet := make([]byte, 24+len(address)+3)
	binary.BigEndian.PutUint64(packet[:8], uint64(flow.StreamID()))
	binary.BigEndian.PutUint64(packet[8:16], 1)
	binary.BigEndian.PutUint16(packet[16:18], 3)
	binary.BigEndian.PutUint16(packet[20:22], uint16(len(address)))
	packet[23] = 1
	copy(packet[24:], address)
	copy(packet[24+len(address):], "udp")
	if err = c.SendDatagram(packet); err != nil {
		t.Fatal(err)
	}
	answer, err = c.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(answer) < 27 || binary.BigEndian.Uint64(answer[:8]) != uint64(flow.StreamID()) || string(answer[len(answer)-3:]) != "udp" {
		t.Fatalf("UDP wire response: %x", answer)
	}
	flow.Close()
}

func put(w io.Writer, b []byte) error {
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}
func checkResponse(t *testing.T, r io.Reader) {
	t.Helper()
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		t.Fatal(err)
	}
	n := binary.BigEndian.Uint32(h[:])
	if n > 4096 {
		t.Fatal("oversized response")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if json.Unmarshal(b, &result) != nil || result["error"] != nil {
		t.Fatalf("response: %s", b)
	}
}
