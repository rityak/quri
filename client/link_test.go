package client

import (
	"strings"
	"testing"

	"github.com/metacubex/tls"
)

func TestProfileLink(t *testing.T) {
	cfg := Config{Address: "relay.example:443", Token: strings.Repeat("a", 32), Ports: []uint16{443, 8443}, Transports: []string{"h3", "h2"}}
	cfg.Transport.TLS = &tls.Config{ServerName: "relay.example"}
	raw, err := Link(cfg)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseLink(raw)
	if err != nil || parsed.Address != cfg.Address || parsed.Token != cfg.Token || len(parsed.Ports) != 2 || len(parsed.Transports) != 2 {
		t.Fatalf("round trip: %+v %v", parsed, err)
	}
	for _, bad := range []string{"quri://weak@relay.example:443", raw + "&insecure=true", raw + "&ports=0", strings.Replace(raw, "transports=h3%2Ch2", "transports=h3%2Ch3", 1)} {
		if _, err := ParseLink(bad); err == nil {
			t.Fatalf("accepted invalid link %q", bad)
		}
	}
}

func FuzzProfileLink(f *testing.F) {
	f.Add("quri://" + strings.Repeat("a", 32) + "@relay.example:443?transports=h3,h2")
	f.Fuzz(func(t *testing.T, raw string) { _, _ = ParseLink(raw) }) //nolint:errcheck // Malformed fuzz inputs are expected to return errors.
}
