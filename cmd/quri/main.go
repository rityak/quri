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
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"unicode/utf8"

	"github.com/metacubex/tls"
	"github.com/rityak/quri/auth"
	"github.com/rityak/quri/certificates"
	"github.com/rityak/quri/client"
	"github.com/rityak/quri/config"
	"github.com/rityak/quri/route"
	"github.com/rityak/quri/session"
	"github.com/rityak/quri/socks5"
	"github.com/rityak/quri/transport"
	"golang.org/x/sync/errgroup"
)

type configFile struct {
	Mode        string        `json:"mode"`
	Listen      string        `json:"listen"`
	Server      string        `json:"server"`
	ServerName  string        `json:"server_name"`
	CA          string        `json:"ca"`
	Certificate string        `json:"certificate"`
	Key         string        `json:"key"`
	Token       string        `json:"token"`
	Allow       []string      `json:"allow"`
	Profile     string        `json:"profile"`
	Upstream    string        `json:"upstream"`
	Website     string        `json:"website"`
	Ports       []uint16      `json:"ports"`
	Transports  []string      `json:"transports"`
	Domain      string        `json:"domain"`
	ACMECache   string        `json:"acme_cache"`
	ACMEEmail   string        `json:"acme_email"`
	Limits      config.Config `json:"limits"`
}

func main() {
	if err := run(); err != nil {
		slog.Error("quri stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	path := flag.String("config", "", "path to a client or server JSON configuration")
	link := flag.String("link", "", "private quri:// client profile")
	listen := flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address when using -link")
	flag.Parse()
	var cfg configFile
	if *path == "" {
		if *link == "" {
			return errors.New("-config or -link is required")
		}
		cfg = configFile{Mode: "client", Profile: *link, Listen: *listen}
	} else {
		file, err := os.Open(*path)
		if err != nil {
			return err
		}
		raw, err := io.ReadAll(io.LimitReader(file, config.DefaultMaxControl+1))
		if err := errors.Join(err, file.Close()); err != nil {
			return err
		}
		if len(raw) > config.DefaultMaxControl || !utf8.Valid(raw) {
			return errors.New("configuration too large")
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&cfg); err != nil {
			return err
		}
		if decoder.Decode(new(any)) != io.EOF {
			return errors.New("invalid trailing configuration")
		}
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
		return serve(ctx, cfg, relative)
	case "client":
		return serveClient(ctx, cfg, relative)
	default:
		return errors.New("mode must be client or server")
	}
}

func serve(ctx context.Context, cfg configFile, relative func(string) string) error {
	var tc *tls.Config
	var files *certificates.Files
	if cfg.Domain != "" {
		if cfg.Certificate != "" || cfg.Key != "" {
			return errors.New("choose ACME or external certificate files")
		}
		var err error
		tc, err = certificates.ACME(cfg.Domain, relative(cfg.ACMECache), cfg.ACMEEmail)
		if err != nil {
			return err
		}
	} else {
		var err error
		files, err = certificates.LoadFiles(relative(cfg.Certificate), relative(cfg.Key))
		if err != nil {
			return err
		}
		tc = &tls.Config{GetCertificate: files.GetCertificate, MinVersion: tls.VersionTLS13}
	}
	website, err := transport.NewWebsiteProxy(cfg.Website, cfg.Limits)
	if err != nil {
		return err
	}
	defer website.Close() //nolint:errcheck // Close only releases idle backend connections after serving stops.
	verifier, err := auth.New(map[string]string{"default": cfg.Token})
	if err != nil {
		return err
	}
	policy := route.DirectPolicy{}
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
	tcp, udp, err := transport.ListenSockets(cfg.Listen)
	if err != nil {
		return err
	}
	_, service, err := net.SplitHostPort(tcp.Addr().String())
	if err != nil {
		return errors.Join(err, tcp.Close(), udp.Close())
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return errors.Join(err, tcp.Close(), udp.Close())
	}
	for _, addr := range addresses {
		prefix, err := netip.ParsePrefix(addr.String())
		if err != nil {
			continue
		}
		endpoint, err := netip.ParseAddrPort(net.JoinHostPort(prefix.Addr().Unmap().String(), service))
		if err != nil {
			return errors.Join(err, tcp.Close(), udp.Close())
		}
		policy.Denied = append(policy.Denied, endpoint)
	}
	handler, err := session.NewServer(func(ctx context.Context, principal string, request session.Request) (route.Route, error) {
		if request.Namespace != "direct" || request.Version != 1 {
			return nil, route.ErrDenied
		}
		if cfg.Upstream != "" {
			upstream, err := client.ParseLink(cfg.Upstream)
			if err != nil {
				return nil, err
			}
			return client.Dial(ctx, upstream)
		}
		return route.NewDirectRoute(policy)
	}, cfg.Limits, slog.Default())
	if err != nil {
		return errors.Join(err, tcp.Close(), udp.Close())
	}
	server, err := transport.NewServer(tcp, udp, transport.ServerOptions{TLS: tc, Auth: verifier, Handler: handler, Website: website, Limits: cfg.Limits})
	if err != nil {
		return errors.Join(err, tcp.Close(), udp.Close())
	}
	fmt.Fprintf(os.Stderr, "quri server listening on %s\n", tcp.Addr())
	ownedCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers errgroup.Group
	workers.Go(func() error { defer cancel(); return server.Serve(ownedCtx) })
	if files != nil {
		workers.Go(func() error { return files.Run(ownedCtx, slog.Default()) })
	}
	return errors.Join(workers.Wait(), handler.Close())
}

func serveClient(ctx context.Context, cfg configFile, relative func(string) string) error {
	profile := client.Config{Address: cfg.Server, Token: cfg.Token, Ports: cfg.Ports, Transports: cfg.Transports, Configuration: session.Request{Namespace: "direct", Version: 1}, Transport: transport.ClientOptions{TLS: &tls.Config{ServerName: cfg.ServerName, MinVersion: tls.VersionTLS13}, Limits: cfg.Limits}}
	if cfg.Profile != "" {
		var err error
		profile, err = client.ParseLink(cfg.Profile)
		if err != nil {
			return err
		}
		profile.Transport.Limits = cfg.Limits
	}
	if cfg.CA != "" {
		raw, err := os.ReadFile(relative(cfg.CA))
		if err != nil {
			return err
		}
		profile.Transport.TLS.RootCAs = x509.NewCertPool()
		if !profile.Transport.TLS.RootCAs.AppendCertsFromPEM(raw) {
			return errors.New("invalid CA certificate")
		}
	}
	manager, err := client.Dial(ctx, profile)
	if err != nil {
		return err
	}
	defer manager.Close() //nolint:errcheck // SOCKS shutdown result takes precedence over transport cleanup.
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "quri SOCKS5 listening on %s\n", listener.Addr())
	return socks5.ServeClient(ctx, listener, manager)
}
