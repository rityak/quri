package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/metacubex/tls"
	"github.com/rityak/quri"
	"github.com/rityak/quri/socks5"
)

type config struct {
	Mode        string   `json:"mode"`
	Listen      string   `json:"listen"`
	Server      string   `json:"server"`
	ServerName  string   `json:"server_name"`
	CA          string   `json:"ca"`
	Certificate string   `json:"certificate"`
	Key         string   `json:"key"`
	Token       string   `json:"token"`
	Allow       []string `json:"allow"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	path := flag.String("config", "", "path to client or server JSON configuration")
	flag.Parse()
	if *path == "" {
		return errors.New("-config is required")
	}
	f, err := os.Open(*path)
	if err != nil {
		return err
	}
	defer f.Close()
	limited := io.LimitReader(f, (1<<20)+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(raw) > 1<<20 {
		return quri.ErrLimit
	}
	var cfg config
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&cfg); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid trailing configuration")
	}
	relative := func(name string) string {
		if name == "" || filepath.IsAbs(name) {
			return name
		}
		return filepath.Join(filepath.Dir(*path), name)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch cfg.Mode {
	case "server":
		cert, err := tls.LoadX509KeyPair(relative(cfg.Certificate), relative(cfg.Key))
		if err != nil {
			return err
		}
		auth, err := quri.TokenAuthenticator(map[quri.Principal]string{"default": cfg.Token})
		if err != nil {
			return err
		}
		policy := quri.DirectPolicy{}
		for _, cidr := range cfg.Allow {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				return err
			}
			policy.Allowed = append(policy.Allowed, prefix)
		}
		if len(policy.Allowed) == 0 {
			return errors.New("server requires an explicit allow CIDR list")
		}
		socket, err := net.ListenPacket("udp", cfg.Listen)
		if err != nil {
			return err
		}
		defer socket.Close()
		_, portText, _ := net.SplitHostPort(socket.LocalAddr().String())
		var port uint16
		if _, err = fmt.Sscan(portText, &port); err != nil {
			return err
		}
		addresses, err := net.InterfaceAddrs()
		if err != nil {
			return err
		}
		for _, addr := range addresses {
			prefix, err := netip.ParsePrefix(addr.String())
			if err == nil {
				policy.Denied = append(policy.Denied, netip.AddrPortFrom(prefix.Addr().Unmap(), port))
			}
		}
		srv, err := quri.Listen(socket, quri.ServerConfig{TLS: &tls.Config{Certificates: []tls.Certificate{cert}}, Authenticate: auth, Configure: func(ctx context.Context, p quri.Principal, r quri.Request) (quri.Route, error) {
			if r.Namespace != "direct" || r.Version != 1 || string(r.Payload) != "{}" {
				return nil, quri.ErrDenied
			}
			return quri.NewDirectRoute(policy)
		}})
		if err != nil {
			return err
		}
		defer func() {
			drain, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			srv.Shutdown(drain)
		}()
		fmt.Fprintf(os.Stderr, "quri server listening on %s\n", srv.Addr())
		return srv.Serve(ctx)
	case "client":
		tc := &tls.Config{ServerName: cfg.ServerName}
		if cfg.CA != "" {
			raw, err := os.ReadFile(relative(cfg.CA))
			if err != nil {
				return err
			}
			tc.RootCAs = x509.NewCertPool()
			if !tc.RootCAs.AppendCertsFromPEM(raw) {
				return errors.New("invalid CA certificate")
			}
		}
		dial, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		session, err := quri.Dial(dial, cfg.Server, quri.ClientConfig{TLS: tc, Token: cfg.Token, Configuration: quri.Request{Namespace: "direct", Version: 1, Payload: []byte("{}")}})
		if err != nil {
			return err
		}
		defer session.Close()
		listener, err := net.Listen("tcp", cfg.Listen)
		if err != nil {
			return err
		}
		defer listener.Close()
		fmt.Fprintf(os.Stderr, "quri SOCKS5 listening on %s\n", listener.Addr())
		serveCtx, stopServe := context.WithCancel(context.Background())
		defer stopServe()
		done := make(chan struct{})
		defer close(done)
		shutdown := make(chan error, 1)
		go func() {
			select {
			case <-ctx.Done():
				listener.Close()
				drain, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				shutdown <- session.Shutdown(drain)
				stopServe()
			case <-done:
			}
		}()
		err = socks5.Serve(serveCtx, listener, session)
		if ctx.Err() != nil {
			return <-shutdown
		}
		return err
	default:
		return errors.New("mode must be client or server")
	}
}
