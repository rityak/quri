package transport

import (
	"net"
	"testing"
)

func TestSharedListenEndpoint(t *testing.T) {
	tcp, udp, err := ListenSockets("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer closeTest(t, tcp)
	defer closeTest(t, udp)
	if tcp.Addr().String() != udp.LocalAddr().String() {
		t.Fatal("TCP and UDP endpoints differ")
	}
	if _, _, err := ListenSockets(tcp.Addr().String()); err == nil {
		t.Fatal("fixed occupied TCP port was accepted")
	}
	if _, port, err := net.SplitHostPort(tcp.Addr().String()); err != nil || port == "0" {
		t.Fatalf("unbound endpoint: %v", err)
	}
}
