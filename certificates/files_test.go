package certificates

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/tls"
	"github.com/rityak/quri/internal/testcert"
)

func TestReloadChangesNewHandshakeAndPreservesExistingConnection(t *testing.T) {
	directory := t.TempDir()
	certPath, keyPath := filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem")

	firstTLS, first := writeCertificateFiles(t, certPath, keyPath)
	files, err := LoadFiles(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
	}()
	connect := func(clientTLS *tls.Config, expected []byte) *tls.Conn {
		t.Helper()
		done := make(chan error, 1)
		go func() {
			raw, err := listener.Accept()
			if err != nil {
				done <- err
				return
			}
			conn := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: files.GetCertificate})
			_, copyErr := io.Copy(conn, conn)
			done <- errors.Join(copyErr, conn.Close())
		}()
		raw, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conn := tls.Client(raw, clientTLS)
		t.Cleanup(func() {
			if err := conn.Close(); err != nil {
				t.Error(err)
			}
			if err := <-done; err != nil {
				t.Error(err)
			}
		})
		if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := conn.Handshake(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(conn.ConnectionState().PeerCertificates[0].Raw, expected) {
			t.Fatal("handshake used the wrong certificate generation")
		}
		return conn
	}
	old := connect(firstTLS, first)
	secondTLS, second := writeCertificateFiles(t, certPath, keyPath)
	if err := files.Reload(); err != nil {
		t.Fatal(err)
	}
	fresh := connect(secondTLS, second)
	for _, conn := range []*tls.Conn{old, fresh} {
		payload := []byte("traffic-after-certificate-renewal")
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("renewal interrupted traffic: %q %v", got, err)
		}
	}
}

func TestCertificateFilesReloadKeepsLastValidPair(t *testing.T) {
	directory := t.TempDir()
	certPath, keyPath := filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem")

	_, first := writeCertificateFiles(t, certPath, keyPath)
	files, err := LoadFiles(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := files.GetCertificate(nil)
	if err != nil || string(initial.Certificate[0]) != string(first) {
		t.Fatalf("initial certificate error=%v", err)
	}
	if err := os.WriteFile(keyPath, []byte("partial renewal"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := files.Reload(); err == nil {
		t.Fatal("accepted incomplete certificate renewal")
	}
	retained, err := files.GetCertificate(nil)
	if err != nil || string(retained.Certificate[0]) != string(first) {
		t.Fatal("failed reload replaced the last valid certificate")
	}
	_, second := writeCertificateFiles(t, certPath, keyPath)
	if err := files.Reload(); err != nil {
		t.Fatal(err)
	}
	renewed, err := files.GetCertificate(nil)
	if err != nil || string(renewed.Certificate[0]) != string(second) {
		t.Fatal("renewed certificate did not reach TLS configuration")
	}
}

func writeCertificateFiles(t *testing.T, certPath, keyPath string) (*tls.Config, []byte) {
	t.Helper()
	server, client := testcert.TLS(t)
	certificate := server.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	return client, certificate.Certificate[0]
}
