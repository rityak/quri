// Package certificates adapts the standard ACME manager to the pinned TLS fork.
package certificates

import (
	stdtls "crypto/tls"
	"errors"
	"strings"

	"github.com/metacubex/tls"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// ACME manages cached certificates using TLS-ALPN-01 on the public TCP port 443.
// Domain validation and issuance are performed only when a client connects.
func ACME(domain, cacheDirectory, email string) (*tls.Config, error) {
	if domain == "" || cacheDirectory == "" || strings.ContainsAny(domain, "\x00\r\n /:*?#") {
		return nil, errors.New("ACME requires a DNS name and persistent cache directory")
	}
	manager := &autocert.Manager{Prompt: autocert.AcceptTOS, Cache: autocert.DirCache(cacheDirectory), HostPolicy: autocert.HostWhitelist(domain), Email: email}
	return &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", acme.ALPNProto}, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		standardHello := &stdtls.ClientHelloInfo{ServerName: hello.ServerName, SupportedProtos: hello.SupportedProtos, CipherSuites: hello.CipherSuites, SupportedVersions: hello.SupportedVersions}
		for _, curve := range hello.SupportedCurves {
			standardHello.SupportedCurves = append(standardHello.SupportedCurves, stdtls.CurveID(curve))
		}
		for _, scheme := range hello.SignatureSchemes {
			standardHello.SignatureSchemes = append(standardHello.SignatureSchemes, stdtls.SignatureScheme(scheme))
		}
		certificate, err := manager.GetCertificate(standardHello)
		if err != nil {
			return nil, err
		}
		return &tls.Certificate{Certificate: certificate.Certificate, PrivateKey: certificate.PrivateKey, OCSPStaple: certificate.OCSPStaple, SignedCertificateTimestamps: certificate.SignedCertificateTimestamps, Leaf: certificate.Leaf}, nil
	}}, nil
}
