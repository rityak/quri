package main

import (
	"context"
	"net/netip"
	"os"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"
)

func TestRelayStartupSupportsLiteralIPv6(t *testing.T) {
	previousArgs, previousIPv6 := os.Args, resolver.DisableIPv6
	t.Cleanup(func() { os.Args, resolver.DisableIPv6 = previousArgs, previousIPv6 })
	os.Args = []string{"quri-relay", "-help"}
	resolver.DisableIPv6 = true
	main()
	ip, err := resolver.ResolveIP(context.Background(), "::1")
	if err != nil || ip != netip.IPv6Loopback() {
		t.Fatalf("standalone IPv6 lookup = %s, %v, want ::1", ip, err)
	}
}
