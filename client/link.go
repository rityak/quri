package client

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"github.com/metacubex/tls"
	"github.com/rityak/quri/auth"
	"github.com/rityak/quri/route"
	"github.com/rityak/quri/session"
)

const linkScheme = "quri"

const maxLinkSize = 16 << 10

// ParseLink imports a verified-TLS quri:// profile. The link itself is a secret.
func ParseLink(raw string) (Config, error) {
	var cfg Config
	if len(raw) > maxLinkSize {
		return cfg, errors.New("profile link too large")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != linkScheme || u.User == nil || (u.Path != "" && u.Path != "/") {
		return cfg, errors.New("invalid quri link")
	}
	if _, hasPassword := u.User.Password(); hasPassword {
		return cfg, errors.New("invalid quri credential")
	}
	if err := route.ValidateAddress(u.Host); err != nil {
		return cfg, err
	}
	cfg.Address, cfg.Token = u.Host, u.User.Username()
	if len(cfg.Token) < auth.MinTokenSize || len(cfg.Token) > auth.MaxTokenSize {
		return cfg, errors.New("invalid quri credential size")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return cfg, err
	}
	for key, values := range query {
		if len(values) != 1 {
			return cfg, errors.New("duplicate profile setting")
		}
		switch key {
		case "sni", "ports", "transports", "config":
		default:
			return cfg, errors.New("unknown profile setting")
		}
	}
	serverName := query.Get("sni")
	if serverName == "" {
		serverName = u.Hostname()
	}
	if len(serverName) > 253 || strings.ContainsAny(serverName, "\x00\r\n /?#") {
		return cfg, errors.New("invalid server name")
	}
	cfg.Transport.TLS = &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS13}
	if ports := query.Get("ports"); ports != "" {
		for _, text := range strings.Split(ports, ",") {
			port, err := strconv.ParseUint(text, 10, 16)
			if err != nil || port == 0 || len(cfg.Ports) >= maxPorts {
				return Config{}, errors.New("invalid profile ports")
			}
			cfg.Ports = append(cfg.Ports, uint16(port))
		}
	}
	if protocols := query.Get("transports"); protocols != "" {
		seen := make(map[string]bool)
		for _, protocol := range strings.Split(protocols, ",") {
			if (protocol != "h3" && protocol != "h2") || seen[protocol] {
				return Config{}, errors.New("invalid profile transports")
			}
			seen[protocol] = true
			cfg.Transports = append(cfg.Transports, protocol)
		}
	}
	cfg.Configuration = session.Request{Namespace: "direct", Version: 1, Payload: json.RawMessage(`{}`)}
	if encoded := query.Get("config"); encoded != "" {
		data, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return Config{}, errors.New("invalid profile configuration")
		}
		if err := json.Unmarshal(data, &cfg.Configuration); err != nil || cfg.Configuration.Namespace == "" || cfg.Configuration.Version == 0 {
			return Config{}, errors.New("invalid profile configuration")
		}
	}
	return cfg, nil
}

// Link exports the profile, including its credential, for private import or QR.
func Link(cfg Config) (string, error) {
	if cfg.Transport.TLS == nil {
		return "", errors.New("missing TLS configuration")
	}
	query := url.Values{}
	query.Set("sni", cfg.Transport.TLS.ServerName)
	if len(cfg.Ports) > 0 {
		ports := make([]string, len(cfg.Ports))
		for i, port := range cfg.Ports {
			ports[i] = strconv.Itoa(int(port))
		}
		query.Set("ports", strings.Join(ports, ","))
	}
	if len(cfg.Transports) > 0 {
		query.Set("transports", strings.Join(cfg.Transports, ","))
	}
	if cfg.Configuration.Namespace != "" {
		data, err := json.Marshal(cfg.Configuration)
		if err != nil {
			return "", err
		}
		query.Set("config", base64.RawURLEncoding.EncodeToString(data))
	}
	u := &url.URL{Scheme: linkScheme, Host: cfg.Address, User: url.User(cfg.Token), RawQuery: query.Encode()}
	raw := u.String()
	if _, err := ParseLink(raw); err != nil {
		return "", err
	}
	return raw, nil
}
