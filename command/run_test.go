package command

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckClientDoesNotDial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.json")
	cfg := Config{Mode: "client", Server: "unresolvable.invalid:443", Token: strings.Repeat("test-token-", 4), Transports: []string{"h3", "h2"}}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), []string{"-check", "-config", path}, nil); err != nil {
		t.Fatal(err)
	}
	cfg.Token = "weak"
	data, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), []string{"-check", "-config", path}, nil); err == nil {
		t.Fatal("check accepted weak credentials")
	}
}
