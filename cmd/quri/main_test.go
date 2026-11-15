package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rityak/quri/internal/testcert"
	"golang.org/x/net/proxy"
)

func TestCLIConfigurationPipeline(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "quri")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %s %v", output, err)
	}
	serverTLS, _ := testcert.TLS(t)
	cert := serverTLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "server.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "server-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	start := func(name string, cfg config, prefix string) string {
		t.Helper()
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name+".json")
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		command := exec.CommandContext(ctx, binary, "-config", path)
		stderr, err := command.StderrPipe()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if err = command.Start(); err != nil {
			cancel()
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		t.Cleanup(func() { cancel(); <-done })
		ready := make(chan string, 1)
		go func() {
			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, prefix) {
					select {
					case ready <- strings.TrimPrefix(line, prefix):
					default:
					}
				}
			}
		}()
		select {
		case addr := <-ready:
			return addr
		case <-time.After(10 * time.Second):
			t.Fatal("CLI did not become ready")
			return ""
		}
	}
	token := strings.Repeat("test-cli-only", 4)
	server := start("server", config{Mode: "server", Listen: "127.0.0.1:0", Certificate: "server.pem", Key: "server-key.pem", Token: token, Allow: []string{"127.0.0.0/8"}}, "quri server listening on ")
	socks := start("client", config{Mode: "client", Listen: "127.0.0.1:0", Server: server, ServerName: "localhost", CA: "server.pem", Token: token}, "quri SOCKS5 listening on ")
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "quri-cli") }))
	defer target.Close()
	dialer, err := proxy.SOCKS5("tcp", socks, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.Dial("tcp", strings.TrimPrefix(target.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "quri-cli" {
		t.Fatal(string(body), err)
	}
}
