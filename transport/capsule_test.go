package transport

import (
	"bytes"
	"testing"
)

func TestCapsuleAndDatagram(t *testing.T) {
	for _, payload := range [][]byte{nil, []byte("udp"), bytes.Repeat([]byte{42}, 1150)} {
		wire := AppendDatagram(nil, payload)
		decoded, err := ParseDatagram(wire, 1150)
		if err != nil || !bytes.Equal(decoded, payload) {
			t.Fatalf("datagram: %x, %v", decoded, err)
		}
		wire = AppendCapsule(nil, payload)
		var buf [1150]byte
		n, err := ReadCapsule(bytes.NewReader(wire), buf[:], len(buf))
		if err != nil || !bytes.Equal(buf[:n], payload) {
			t.Fatalf("capsule: %x, %v", buf[:n], err)
		}
	}
	if _, err := ParseDatagram([]byte{1, 2}, 1150); err == nil {
		t.Fatal("unknown context accepted")
	}
}

func FuzzDatagram(f *testing.F) {
	f.Add([]byte{0, 1})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = ParseDatagram(data, 1150) }) //nolint:errcheck // Malformed fuzz inputs are expected to return errors.
}

func FuzzCapsule(f *testing.F) {
	f.Add([]byte{0, 2, 0, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		var dst [1150]byte
		_, _ = ReadCapsule(bytes.NewReader(data), dst[:], len(dst)) //nolint:errcheck // Malformed fuzz inputs are expected to return errors.
	})
}

func BenchmarkDatagramCodec(b *testing.B) {
	var dst [1200]byte
	var payload [1150]byte
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		wire := AppendDatagram(dst[:0], payload[:])
		if _, err := ParseDatagram(wire, len(payload)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCapsuleDecode(b *testing.B) {
	wire := AppendCapsule(nil, make([]byte, 1150))
	r := bytes.NewReader(wire)
	var dst [1150]byte
	var scratch [8]byte
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r.Reset(wire)
		if n, err := readCapsule(r, dst[:], len(dst), &scratch); err != nil || n != len(dst) {
			b.Fatalf("capsule decode: %d %v", n, err)
		}
	}
}
