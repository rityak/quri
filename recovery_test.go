package quri

import (
	"context"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type refusedPacketConn struct {
	net.PacketConn
	refused atomic.Bool
	drop    atomic.Bool
}

func (p *refusedPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := p.PacketConn.ReadFrom(b)
	if p.refused.Swap(false) {
		p.PacketConn.SetReadDeadline(time.Time{})
		return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: syscall.ECONNREFUSED}
	}
	return n, addr, err
}

func (p *refusedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if p.drop.Load() {
		return len(b), nil
	}
	return p.PacketConn.WriteTo(b, addr)
}

func TestRefusedPathVerification(t *testing.T) {
	for _, drop := range []bool{false, true} {
		t.Run(map[bool]string{false: "stale", true: "unreachable"}[drop], func(t *testing.T) {
			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			fault := &refusedPacketConn{PacketConn: pc}
			s, _ := testPair(t, fault)
			fault.drop.Store(drop)
			fault.refused.Store(true)
			pc.SetReadDeadline(time.Now())
			ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
			defer cancel()
			if drop {
				select {
				case <-s.Done():
				case <-ctx.Done():
					t.Fatal("failed path was not closed after bounded verification")
				}
				return
			}
			for {
				s.mu.Lock()
				verified := s.nextID >= 2 && s.pending == nil
				s.mu.Unlock()
				if verified {
					break
				}
				select {
				case <-s.Done():
					t.Fatal("stale ICMP closed a healthy session")
				case <-ctx.Done():
					t.Fatal("path verification did not complete")
				case <-time.After(time.Millisecond):
				}
			}
			if err := s.Probe(ctx); err != nil {
				t.Fatal(err)
			}
			if s.handle != 1 {
				t.Fatalf("route handle changed: %d", s.handle)
			}
		})
	}
}
