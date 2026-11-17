// Package command runs the standalone client and relay with optional host outbounds.
package command

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
	"path/filepath"
	"strings"
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

// Config is the shared client/server JSON configuration.
type Config struct {
	Mode                string            `json:"mode"`
	Listen              string            `json:"listen"`
	Server              string            `json:"server"`
	ServerName          string            `json:"server_name"`
	CA                  string            `json:"ca"`
	Certificate         string            `json:"certificate"`
	Key                 string            `json:"key"`
	Token               string            `json:"token"`
	Allow               []string          `json:"allow"`
	Profile             string            `json:"profile"`
	Upstream            string            `json:"upstream"`
	AllowClientUpstream bool              `json:"allow_client_upstream"`
	Tokens              map[string]string `json:"tokens"`
	Website             string            `json:"website"`
	Ports               []uint16          `json:"ports"`
	Transports          []string          `json:"transports"`
	Domain              string            `json:"domain"`
	ACMECache           string            `json:"acme_cache"`
	ACMEEmail           string            `json:"acme_email"`
	Limits              config.Config     `json:"limits"`
}

// UpstreamFactory constructs one host-owned outbound, such as a miray VLESS adapter.
type UpstreamFactory func(context.Context, string) (route.Route, error)

const (
	clientMode = "client"
	serverMode = "server"
)

// Run parses arguments without process-global flags and serves until ctx ends.
func Run(ctx context.Context, args []string, upstream UpstreamFactory) error {
	flags := flag.NewFlagSet("quri", flag.ContinueOnError)
	path := flags.String("config", "", "path to a client or server JSON configuration")
	link := flags.String("link", "", "private quri:// client profile")
	listen := flags.String("listen", "127.0.0.1:1080", "SOCKS5 listen address when using -link")
	export := flags.Bool("export-link", false, "print the private quri:// profile and exit")
	qrPath := flags.String("qr", "", "write a private QR PNG file and exit")
	check := flags.Bool("check", false, "validate configuration without opening sockets")
	serviceCheck := flags.Bool("check-service", false, "validate server configuration with absolute file paths")
	if err := flags.Parse(args); err != nil {
		return err
	}
	var cfg Config
	if *path == "" {
		if *link == "" {
			return errors.New("-config or -link is required")
		}
		cfg = Config{Mode: clientMode, Profile: *link, Listen: *listen}
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
	if *export || *qrPath != "" {
		if cfg.Mode != clientMode {
			return errors.New("profile export requires a client configuration")
		}
		profile, err := clientProfile(cfg, relative)
		if err != nil {
			return err
		}
		link, err := client.Link(profile)
		if err != nil {
			return err
		}
		if *qrPath != "" {
			if err := writeQR(link, *qrPath); err != nil {
				return err
			}
		}
		if *export {
			if _, err := fmt.Fprintln(os.Stdout, link); err != nil {
				return err
			}
		}
		return nil
	}
	if *serviceCheck {
		if cfg.Mode != serverMode {
			return errors.New("service configuration must use server mode")
		}
		for _, path := range []string{cfg.Certificate, cfg.Key, cfg.CA, cfg.ACMECache} {
			if path != "" && !filepath.IsAbs(path) {
				return errors.New("service certificate, key and cache paths must be absolute")
			}
		}
	}
	if *check || *serviceCheck {
		return validate(ctx, cfg, relative, upstream)
	}
	switch cfg.Mode {
	case serverMode:
		return serve(ctx, cfg, relative, upstream)
	case clientMode:
		return serveClient(ctx, cfg, relative)
	default:
		return errors.New("mode must be client or server")
	}
}

func validate(ctx context.Context, cfg Config, relative func(string) string, upstream UpstreamFactory) error {
	if err := cfg.Limits.WithDefaults().Validate(); err != nil {
		return err
	}
	switch cfg.Mode {
	case serverMode:
		website, err := transport.NewWebsiteProxy(cfg.Website, cfg.Limits)
		if err != nil {
			return err
		}
		if err := website.Close(); err != nil {
			return err
		}
		tokens := cfg.Tokens
		if cfg.Token != "" {
			if len(tokens) != 0 {
				return errors.New("choose token or tokens")
			}
			tokens = map[string]string{"default": cfg.Token}
		}
		if _, err := auth.New(tokens); err != nil {
			return err
		}
		var policy route.DirectPolicy
		for _, text := range cfg.Allow {
			prefix, err := netip.ParsePrefix(text)
			if err != nil {
				return err
			}
			policy.Allowed = append(policy.Allowed, prefix)
		}
		if _, err := route.NewDirectRoute(policy); err != nil {
			return err
		}
		if cfg.Domain != "" {
			if cfg.Certificate != "" || cfg.Key != "" {
				return errors.New("choose ACME or external certificate files")
			}
			if _, err := certificates.ACME(cfg.Domain, relative(cfg.ACMECache), cfg.ACMEEmail); err != nil {
				return err
			}
		} else {
			if _, err := certificates.LoadFiles(relative(cfg.Certificate), relative(cfg.Key)); err != nil {
				return err
			}
		}
		if cfg.Upstream != "" {
			if strings.HasPrefix(cfg.Upstream, "quri://") {
				if _, err := client.ParseLink(cfg.Upstream); err != nil {
					return err
				}
			} else {
				if upstream == nil {
					return errors.New("this outbound requires quri-relay")
				}
				outbound, err := upstream(ctx, cfg.Upstream)
				if err != nil {
					return err
				}
				if err := outbound.Close(); err != nil {
					return err
				}
			}
		}
		_, port, err := net.SplitHostPort(cfg.Listen)
		if err != nil {
			return err
		}
		if _, err := net.LookupPort("tcp", port); err != nil {
			return err
		}
		return nil
	case clientMode:
		if cfg.Profile != "" {
			_, err := client.ParseLink(cfg.Profile)
			return err
		}
		_, err := client.Link(client.Config{Address: cfg.Server, Token: cfg.Token, Ports: cfg.Ports, Transports: cfg.Transports, Transport: transport.ClientOptions{TLS: &tls.Config{ServerName: cfg.ServerName, MinVersion: tls.VersionTLS13}}})
		return err
	default:
		return errors.New("mode must be client or server")
	}
}

func serve(ctx context.Context, cfg Config, relative func(string) string, upstream UpstreamFactory) error {
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
	tokens := cfg.Tokens
	if cfg.Token != "" {
		if len(tokens) != 0 {
			return errors.New("choose token or tokens")
		}
		tokens = map[string]string{"default": cfg.Token}
	}
	verifier, err := auth.New(tokens)
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
		if request.Version != 1 {
			return nil, route.ErrDenied
		}
		link := cfg.Upstream
		switch request.Namespace {
		case "direct":
		case "upstream":
			if !cfg.AllowClientUpstream {
				return nil, route.ErrDenied
			}
			var requested struct {
				URL string `json:"url"`
			}
			decoder := json.NewDecoder(bytes.NewReader(request.Payload))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&requested) != nil || decoder.Decode(new(any)) != io.EOF || len(requested.URL) == 0 || len(requested.URL) > 16384 {
				return nil, route.ErrDenied
			}
			link = requested.URL
		default:
			return nil, route.ErrDenied
		}
		if link != "" {
			if strings.HasPrefix(link, "quri://") {
				profile, err := client.ParseLink(link)
				if err != nil {
					return nil, err
				}
				return client.Dial(ctx, profile)
			}
			if upstream == nil {
				return nil, errors.New("this outbound requires the quri-relay host binary")
			}
			return upstream(ctx, link)
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

func clientProfile(cfg Config, relative func(string) string) (client.Config, error) {
	profile := client.Config{Address: cfg.Server, Token: cfg.Token, Ports: cfg.Ports, Transports: cfg.Transports, Configuration: session.Request{Namespace: "direct", Version: 1}, Transport: transport.ClientOptions{TLS: &tls.Config{ServerName: cfg.ServerName, MinVersion: tls.VersionTLS13}, Limits: cfg.Limits}}
	if cfg.Profile != "" {
		var err error
		profile, err = client.ParseLink(cfg.Profile)
		if err != nil {
			return client.Config{}, err
		}
		profile.Transport.Limits = cfg.Limits
	}
	if cfg.Upstream != "" {
		payload, err := json.Marshal(struct {
			URL string `json:"url"`
		}{cfg.Upstream})
		if err != nil {
			return client.Config{}, err
		}
		profile.Configuration = session.Request{Namespace: "upstream", Version: 1, Payload: payload}
	}
	if cfg.CA != "" {
		raw, err := os.ReadFile(relative(cfg.CA))
		if err != nil {
			return client.Config{}, err
		}
		profile.Transport.TLS.RootCAs = x509.NewCertPool()
		if !profile.Transport.TLS.RootCAs.AppendCertsFromPEM(raw) {
			return client.Config{}, errors.New("invalid CA certificate")
		}
	}
	return profile, nil
}

func serveClient(ctx context.Context, cfg Config, relative func(string) string) error {
	profile, err := clientProfile(cfg, relative)
	if err != nil {
		return err
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
