package config

import "testing"

func TestDefaultsAndResourceBounds(t *testing.T) {
	if err := (Config{}).WithDefaults().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, limits := range []Config{{MaxConnections: -1}, {MaxStreams: 1025}, {MaxUDPTargets: 257}, {MaxDatagram: 65508}, {MaxControl: DefaultMaxControl + 1}, {QueueSize: 257}, {OpenTimeout: -1}, {FallbackDelay: DefaultHandshakeTimeout}} {
		if err := limits.WithDefaults().Validate(); err == nil {
			t.Fatalf("accepted unbounded config: %+v", limits)
		}
	}
}
