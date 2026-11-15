package route

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestDirectPolicySnapshotAndDeniedOverride(t *testing.T) {
	policy := DirectPolicy{Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Denied: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:443")}}
	r, err := NewDirectRoute(policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.Allowed[0] = netip.MustParsePrefix("0.0.0.0/0")
	for _, address := range []string{"127.0.0.1:443", "192.0.2.1:443"} {
		if _, err := r.Resolve(context.Background(), address); err != ErrDenied {
			t.Fatalf("policy accepted %s: %v", address, err)
		}
	}
	if _, err := r.Resolve(context.Background(), "127.0.0.1:53"); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkDirectUDPRoundTrip(b *testing.B) {
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var buf [512]byte
		for {
			n, addr, err := target.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				return
			}
			if _, err := target.WriteToUDPAddrPort(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	defer func() {
		if err := target.Close(); err != nil {
			b.Error(err)
		}
		<-done
	}()
	r, err := NewDirectRoute(DirectPolicy{Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	if err != nil {
		b.Fatal(err)
	}
	packet, err := r.ListenPacket(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := packet.Close(); err != nil {
			b.Error(err)
		}
	}()
	address, err := UDPAddress(target.LocalAddr().String())
	if err != nil {
		b.Fatal(err)
	}
	if err := packet.SetReadDeadline(time.Now().Add(time.Minute)); err != nil {
		b.Fatal(err)
	}
	var payload, reply [512]byte
	exchange := func() {
		if _, err := packet.WriteTo(payload[:], address); err != nil {
			b.Fatal(err)
		}
		if n, _, err := packet.ReadFrom(reply[:]); err != nil || n != len(payload) {
			b.Fatalf("UDP read bytes=%d error=%v", n, err)
		}
	}
	for i := 0; i < 16; i++ {
		exchange()
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exchange()
	}
	b.StopTimer()
}
