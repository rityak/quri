package command

import (
	"context"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liyue201/goqr"
	"github.com/rityak/quri/client"
)

func TestExportedQRDecodesToImportableProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.png")
	link := "quri://" + strings.Repeat("test-token-", 4) + "@relay.example:443?sni=relay.example&transports=h3,h2"
	if err := Run(context.Background(), []string{"-link", link, "-qr", path}, nil); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path) //nolint:gosec // The test creates this path inside t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	image, err := png.Decode(file)
	if closeErr := file.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	codes, err := goqr.Recognize(image)
	if err != nil || len(codes) != 1 {
		t.Fatalf("QR decode: count=%d error=%v", len(codes), err)
	}
	profile, err := client.ParseLink(string(codes[0].Payload))
	if err != nil || profile.Address != "relay.example:443" || profile.Token != strings.Repeat("test-token-", 4) {
		t.Fatal("decoded QR did not preserve the client profile")
	}
	if err := Run(context.Background(), []string{"-link", link, "-qr", path}, nil); err == nil {
		t.Fatal("QR export overwrote an existing private file")
	}
}
