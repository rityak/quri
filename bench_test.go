package quri

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

func BenchmarkUDP(b *testing.B) {
	for _, size := range []int{64, 1200, 8192, 65507} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			session, _ := testPair(b)
			target, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer target.Close()
			go func() {
				buf := make([]byte, 65535)
				for {
					n, addr, err := target.ReadFrom(buf)
					if err != nil {
						return
					}
					target.WriteTo(buf[:n], addr)
				}
			}()
			packet, err := session.ListenPacket(context.Background())
			if err != nil {
				b.Fatal(err)
			}
			defer packet.Close()
			payload := make([]byte, size)
			reply := make([]byte, 65535)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				packet.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err = packet.WriteTo(payload, target.LocalAddr()); err != nil {
					b.Fatal(err)
				}
				n, _, err := packet.ReadFrom(reply)
				if err != nil || n != size {
					b.Fatalf("response: %d %v", n, err)
				}
			}
		})
	}
}
