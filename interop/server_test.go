package interop_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rityak/quri"
	"github.com/rityak/quri/internal/testcert"
)

func stockServer(t *testing.T, credit int64) (string, quri.ClientConfig) {
	t.Helper()
	serverTLS, clientTLS := testcert.TLS(t)
	cert := serverTLS.Certificates[0]
	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}},
		NextProtos:   []string{"quri/1"},
	}, &quic.Config{EnableDatagrams: true, MaxIncomingStreams: credit, KeepAlivePeriod: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		defer c.CloseWithError(0, "test complete")
		if credit < 0 {
			<-c.Context().Done()
			return
		}
		if err := serveStock(ctx, c); err != nil && ctx.Err() == nil && c.Context().Err() == nil {
			var closed *quic.ApplicationError
			if !errors.As(err, &closed) {
				t.Errorf("stock server: %v", err)
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		ln.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("stock server did not stop")
		}
	})
	return ln.Addr().String(), quri.ClientConfig{TLS: clientTLS, Token: strings.Repeat("test", 8), Configuration: quri.Request{Namespace: "direct", Version: 1, Payload: []byte("{}")}}
}

func stockBlob(r io.Reader) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n > 2<<20 {
		return nil, errors.New("oversized frame")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func serveStock(ctx context.Context, c *quic.Conn) error {
	control, err := c.AcceptStream(ctx)
	if err != nil {
		return err
	}
	if _, err = stockBlob(control); err != nil {
		return err
	}
	if err = put(control, []byte("{}")); err != nil {
		return err
	}
	controlDone := make(chan struct{})
	go func() {
		defer close(controlDone)
		for {
			var h [13]byte
			if _, err := io.ReadFull(control, h[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(h[9:])
			if n > 2<<20 {
				return
			}
			b := make([]byte, n)
			if _, err := io.ReadFull(control, b); err != nil {
				return
			}
			var req struct {
				Payload []byte `json:"payload"`
			}
			if json.Unmarshal(b, &req) != nil {
				return
			}
			var response []byte
			if h[0] == 1 {
				response = []byte(`{"handle":1}`)
			} else {
				response, _ = json.Marshal(struct {
					Payload []byte `json:"payload,omitempty"`
				}{Payload: req.Payload})
			}
			h[0] |= 0x80
			binary.BigEndian.PutUint32(h[9:], uint32(len(response)))
			if _, err := control.Write(append(h[:], response...)); err != nil {
				return
			}
		}
	}()
	defer func() { control.CancelRead(0); <-controlDone }()
	for {
		st, err := c.AcceptStream(ctx)
		if err != nil {
			return err
		}
		b, err := stockBlob(st)
		if err != nil {
			return err
		}
		var open struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal(b, &open) != nil {
			return errors.New("invalid open")
		}
		if err := put(st, []byte("{}")); err != nil {
			return err
		}
		if open.Kind == "tcp" {
			if _, err := io.Copy(st, st); err != nil {
				return err
			}
			st.Close()
		} else {
			packet, err := c.ReceiveDatagram(ctx)
			if err != nil {
				return err
			}
			if err := c.SendDatagram(packet); err != nil {
				return err
			}
			if _, err := io.Copy(io.Discard, st); err != nil {
				return err
			}
			st.Close()
		}
	}
}

func TestStockQUICServer(t *testing.T) {
	address, cfg := stockServer(t, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := quri.Dial(ctx, address, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	st, err := s.DialContext(ctx, "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err = st.Write([]byte("sdk")); err != nil {
		t.Fatal(err)
	}
	if err = st.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(st)
	if err != nil || string(b) != "sdk" {
		t.Fatalf("TCP = %q, %v", b, err)
	}
	pc, err := s.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	pc.SetDeadline(time.Now().Add(time.Second))
	if _, err = pc.WriteTo([]byte("udp"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}); err != nil {
		t.Fatal(err)
	}
	b = make([]byte, 10)
	n, _, err := pc.ReadFrom(b)
	if err != nil || string(b[:n]) != "udp" {
		t.Fatalf("UDP = %q, %v", b[:n], err)
	}
	b, err = s.Message(ctx, quri.Request{Namespace: "echo", Version: 1, Payload: []byte("control")})
	if err != nil || string(b) != "control" {
		t.Fatalf("control = %q, %v", b, err)
	}
}

func TestSDKStreamCreditDeadline(t *testing.T) {
	for _, credit := range []int64{-1, 1} {
		t.Run(fmt.Sprint(credit), func(t *testing.T) {
			address, cfg := stockServer(t, credit)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			start := time.Now()
			s, err := quri.Dial(ctx, address, cfg)
			if credit == 1 {
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				_, err = s.DialContext(ctx, "example.org:443")
			}
			elapsed := time.Since(start)
			if err == nil || elapsed > 7*time.Second {
				t.Fatalf("stream credit %d: err=%v elapsed=%v, want bounded five-second failure", credit, err, elapsed)
			}
		})
	}
}
