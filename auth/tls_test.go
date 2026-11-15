package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rityak/quri/internal/testcert"
)

func TestProofAcrossRealTLSSessions(t *testing.T) {
	serverConfig, clientConfig := testcert.TLS(t)
	certificate := serverConfig.Certificates[0]
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	defer func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	}()
	token := strings.Repeat("tls-bound-test", 3)
	verifier, err := New(map[string]string{"test": token})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- func() error {
			for attempt := 0; attempt < 2; attempt++ {
				raw, err := listener.Accept()
				if err != nil {
					return err
				}
				conn := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: certificate.Certificate, PrivateKey: certificate.PrivateKey}}})
				deadline, _ := ctx.Deadline()
				if err := conn.SetDeadline(deadline); err != nil {
					return errors.Join(err, conn.Close())
				}
				if err := conn.HandshakeContext(ctx); err != nil {
					return errors.Join(err, conn.Close())
				}
				state := conn.ConnectionState()
				binding, err := Binding(state.ExportKeyingMaterial)
				if err != nil {
					return errors.Join(err, conn.Close())
				}
				proof := make([]byte, 43)
				if _, err := io.ReadFull(conn, proof); err != nil {
					return errors.Join(err, conn.Close())
				}
				_, accepted := verifier.Verify(string(proof), binding)
				result := byte(0)
				if accepted {
					result = 1
				}
				_, err = conn.Write([]byte{result})
				if closeErr := conn.Close(); err != nil || closeErr != nil {
					return errors.Join(err, closeErr)
				}
			}
			return nil
		}()
	}()
	defer func() {
		// Cancel an unfinished Accept before waiting for its goroutine.
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-ctx.Done():
			t.Error("TLS authentication server did not stop")
		}
	}()
	var proof string
	for attempt := 0; attempt < 2; attempt++ {
		dialer := tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: clientConfig.RootCAs, ServerName: "localhost"}}
		raw, err := dialer.DialContext(ctx, "tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conn := raw.(*tls.Conn)
		if attempt == 0 {
			state := conn.ConnectionState()
			binding, err := Binding(state.ExportKeyingMaterial)
			if err != nil {
				t.Fatal(err)
			}
			proof, err = Proof(token, binding)
			if err != nil {
				t.Fatal(err)
			}
		}
		if _, err := io.WriteString(conn, proof); err != nil {
			t.Fatal(err)
		}
		var accepted [1]byte
		if _, err := io.ReadFull(conn, accepted[:]); err != nil {
			t.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		want := byte(1 - attempt)
		if accepted[0] != want {
			t.Errorf("connection %d accepted=%d, want %d", attempt, accepted[0], want)
		}
	}
}
