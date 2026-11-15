package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/tls"
)

func TestACMECachedCertificateAndHostPolicy(t *testing.T) {
	const domain = "relay.example"
	directory := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{domain}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKey})
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	if err := os.WriteFile(filepath.Join(directory, domain), data, 0600); err != nil {
		t.Fatal(err)
	}
	config, err := ACME(domain, directory, "owner@example.org")
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := config.GetCertificate(&tls.ClientHelloInfo{ServerName: domain, SupportedProtos: []string{"h2"}, SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}, SupportedCurves: []tls.CurveID{tls.CurveP256}, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}})
	if err != nil {
		t.Fatal(err)
	}
	if len(certificate.Certificate) != 1 || certificate.Leaf == nil || certificate.Leaf.VerifyHostname(domain) != nil {
		t.Fatal("cached certificate did not reach TLS config")
	}
	if _, err := config.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example"}); err == nil {
		t.Fatal("ACME attempted an unauthorized hostname")
	}
	for _, invalid := range []string{"", "bad:name", "bad/name"} {
		if _, err := ACME(invalid, directory, ""); err == nil {
			t.Fatalf("accepted domain %q", invalid)
		}
	}
}
