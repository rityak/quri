package transport

import (
	"errors"
	"net"
	"net/url"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httputil"
	"github.com/rityak/quri/config"
)

// WebsiteProxy forwards ordinary HTTP requests to one operator-owned website.
// It does not listen on a socket or serve bundled content.
type WebsiteProxy struct {
	proxy     *httputil.ReverseProxy
	transport *http.Transport
}

// NewWebsiteProxy requires an explicit HTTP(S) backend and owns its connection pool.
func NewWebsiteProxy(address string, limits config.Config) (*WebsiteProxy, error) {
	limits = limits.WithDefaults()
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	target, err := url.Parse(address)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Hostname() == "" || target.User != nil || target.Fragment != "" {
		return nil, errors.New("website requires an HTTP(S) backend URL without credentials or fragment")
	}
	pool := &http.Transport{DialContext: (&net.Dialer{Timeout: limits.OpenTimeout, KeepAlive: limits.IdleTimeout}).DialContext,
		ForceAttemptHTTP2: true, TLSHandshakeTimeout: limits.HandshakeTimeout, ResponseHeaderTimeout: limits.OpenTimeout,
		MaxIdleConns: limits.MaxConnections, MaxIdleConnsPerHost: limits.MaxConnections, MaxConnsPerHost: limits.MaxConnections, IdleConnTimeout: limits.IdleTimeout}
	proxy := &httputil.ReverseProxy{Transport: pool, Rewrite: func(request *httputil.ProxyRequest) {
		request.SetURL(target)
		request.Out.Host = request.In.Host
		request.SetXForwarded()
	}, ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}}
	return &WebsiteProxy{proxy: proxy, transport: pool}, nil
}

// ServeHTTP preserves the backend's status, headers and streamed response body.
func (p *WebsiteProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) { p.proxy.ServeHTTP(w, r) }

// Close releases idle backend connections after the relay has stopped serving.
func (p *WebsiteProxy) Close() error { p.transport.CloseIdleConnections(); return nil }
