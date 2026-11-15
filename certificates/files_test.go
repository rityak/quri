package certificates

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/rityak/quri/internal/testcert"
)

func TestCertificateFilesReloadKeepsLastValidPair(t *testing.T) {
	directory := t.TempDir()
	certPath, keyPath := filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem")
	writePair := func() []byte {
		t.Helper()
		server, _ := testcert.TLS(t)
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
		return certificate.Certificate[0]
	}
	first := writePair()
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
	second := writePair()
	if err := files.Reload(); err != nil {
		t.Fatal(err)
	}
	renewed, err := files.GetCertificate(nil)
	if err != nil || string(renewed.Certificate[0]) != string(second) {
		t.Fatal("renewed certificate did not reach TLS configuration")
	}
}
