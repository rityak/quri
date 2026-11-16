// Package client owns transport selection, health checks and reconnection.
package client

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/rityak/quri/auth"
	"github.com/rityak/quri/config"
	"github.com/rityak/quri/session"
	"github.com/rityak/quri/transport"
	"golang.org/x/sync/errgroup"
)

const (
	maxParallelDials = 4
	maxCandidates    = 32
	maxPorts         = 16
	initialBackoff   = 100 * time.Millisecond
	maximumBackoff   = 5 * time.Second
)

// Config is a session profile with one fixed relay outbound.
type Config struct {
	Address       string
	Token         string
	Ports         []uint16
	Transports    []string
	Configuration session.Request
	Transport     transport.ClientOptions
	Resolve       func(context.Context, string) ([]netip.Addr, error)
}

// Manager owns one current session; reconnect never resumes a TCP byte stream.
type Manager struct {
	cfg      Config
	limits   config.Config
	ctx      context.Context
	cancel   context.CancelFunc
	group    errgroup.Group
	mu       sync.Mutex
	current  *session.Session
	changed  chan struct{}
	closed   bool
	packets  map[*packetConn]struct{}
	once     sync.Once
	closeErr error
}

// Dial establishes the first session, then starts the owned health worker.
func Dial(ctx context.Context, cfg Config) (*Manager, error) {
	cfg.Transport.Limits = cfg.Transport.Limits.WithDefaults()
	if err := cfg.Transport.Limits.Validate(); err != nil {
		return nil, err
	}
	if len(cfg.Token) < auth.MinTokenSize || len(cfg.Token) > auth.MaxTokenSize {
		return nil, errors.New("invalid credential size")
	}
	for _, port := range cfg.Ports {
		if port == 0 {
			return nil, errors.New("invalid relay port")
		}
	}
	if len(cfg.Transports) == 0 {
		cfg.Transports = []string{"h3", "h2"}
	}
	if len(cfg.Transports) > 2 || len(cfg.Ports) > maxPorts {
		return nil, errors.New("too many transport candidates")
	}
	seen := make(map[string]bool)
	for _, protocol := range cfg.Transports {
		if (protocol != "h3" && protocol != "h2") || seen[protocol] {
			return nil, errors.New("invalid transport list")
		}
		seen[protocol] = true
	}
	cfg.Ports = append([]uint16(nil), cfg.Ports...)
	cfg.Transports = append([]string(nil), cfg.Transports...)
	cfg.Configuration.Payload = append([]byte(nil), cfg.Configuration.Payload...)
	if cfg.Transport.TLS == nil {
		return nil, errors.New("verified TLS is required")
	}
	cfg.Transport.TLS = cfg.Transport.TLS.Clone()
	if cfg.Transport.TLS.RootCAs != nil {
		cfg.Transport.TLS.RootCAs = cfg.Transport.TLS.RootCAs.Clone()
	}
	host, _, err := net.SplitHostPort(cfg.Address)
	if err != nil {
		return nil, err
	}
	if cfg.Transport.TLS.ServerName == "" {
		cfg.Transport.TLS.ServerName = host
	}
	ownedCtx, cancel := context.WithCancel(context.Background())
	m := &Manager{cfg: cfg, limits: cfg.Transport.Limits, ctx: ownedCtx, cancel: cancel, changed: make(chan struct{}), packets: make(map[*packetConn]struct{})}
	m.current, err = m.connect(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	m.group.Go(m.run)
	return m, nil
}

type candidate struct{ address, protocol string }

// Migrate refreshes the current h3 path after a host network change.
// HTTP/2 requires reconnection and returns transport.ErrMigrationUnsupported.
func (m *Manager) Migrate(ctx context.Context) error {
	current, err := m.currentSession(ctx)
	if err != nil {
		return err
	}
	return current.Migrate(ctx)
}

func (m *Manager) candidates(ctx context.Context) ([]candidate, error) {
	host, service, err := net.SplitHostPort(m.cfg.Address)
	if err != nil {
		return nil, err
	}
	primary, err := strconv.Atoi(service)
	if err != nil || primary < 1 || primary > 65535 {
		return nil, errors.New("invalid relay port")
	}
	resolve := m.cfg.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	ips, err := resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("relay has no addresses")
	}
	var v4, v6 []netip.Addr
	preferV4 := m.cfg.Resolve != nil && len(ips) > 0 && ips[0].Unmap().Is4()
	for _, ip := range ips {
		ip = ip.Unmap()
		if ip.IsValid() {
			if ip.Is4() {
				v4 = append(v4, ip)
			} else {
				v6 = append(v6, ip)
			}
		}
	}
	ips = nil
	for len(v4)+len(v6) > 0 {
		if preferV4 && len(v4) > 0 {
			ips = append(ips, v4[0])
			v4 = v4[1:]
		}
		if len(v6) > 0 {
			ips = append(ips, v6[0])
			v6 = v6[1:]
		}
		if !preferV4 && len(v4) > 0 {
			ips = append(ips, v4[0])
			v4 = v4[1:]
		}
	}
	ports := append([]uint16{uint16(primary)}, m.cfg.Ports...)
	seen := make(map[candidate]bool)
	var result []candidate
	for _, port := range ports {
		if port == 0 {
			return nil, errors.New("invalid relay port")
		}
		for _, ip := range ips {
			for _, protocol := range m.cfg.Transports {
				c := candidate{net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), protocol}
				if !seen[c] {
					seen[c] = true
					result = append(result, c)
				}
				if len(result) == maxCandidates {
					return result, nil
				}
			}
		}
	}
	return result, nil
}

func (m *Manager) connect(ctx context.Context) (*session.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, m.limits.HandshakeTimeout+m.limits.OpenTimeout)
	defer cancel()
	candidates, err := m.candidates(ctx)
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, errors.New("no relay candidates")
	}
	raceCtx, stop := context.WithCancel(ctx)
	type result struct {
		conn *transport.Conn
		err  error
	}
	results := make(chan result, maxParallelDials)
	var workers errgroup.Group
	active, next := 0, 0
	launch := func() {
		c := candidates[next]
		next++
		active++
		workers.Go(func() error {
			options := m.cfg.Transport
			options.Protocol = c.protocol
			conn, err := transport.Dial(raceCtx, c.address, options)
			results <- result{conn, err}
			return nil
		})
	}
	launch()
	timer := time.NewTimer(m.limits.FallbackDelay)
	defer timer.Stop()
	var winner *transport.Conn
	var dialErr error
	for active > 0 && winner == nil {
		select {
		case res := <-results:
			active--
			if res.err == nil {
				winner = res.conn
				break
			}
			dialErr = res.err
			if next < len(candidates) {
				launch()
				timer.Reset(m.limits.FallbackDelay)
			}
		case <-timer.C:
			if next < len(candidates) && active < maxParallelDials {
				launch()
				timer.Reset(m.limits.FallbackDelay)
			}
		case <-ctx.Done():
			dialErr = ctx.Err()
			stop()
		}
	}
	stop()
	_ = workers.Wait() //nolint:errcheck // Workers report errors through the bounded results channel. All workers return nil and report failures through their result channel.
	for active > 0 {
		res := <-results
		active--
		if res.conn != nil {
			_ = res.conn.Close() //nolint:errcheck // Cancellation cleanup cannot change the completed operation result.
		} // Losing handshakes never authenticate or configure.
	}
	if winner == nil {
		return nil, dialErr
	}
	return session.New(ctx, winner, m.cfg.Token, m.cfg.Configuration, m.limits)
}

func (m *Manager) run() error {
	defer m.cancel()
	backoff := initialBackoff
	for {
		m.mu.Lock()
		current := m.current
		m.mu.Unlock()
		select {
		case <-m.ctx.Done():
			return nil
		case <-current.Done():
		}
		_ = current.Close() //nolint:errcheck // Terminated streams cannot migrate into a replacement session. Cancellation cleanup cannot change the completed operation result.
		for {
			if m.ctx.Err() != nil {
				return nil
			}
			next, err := m.connect(m.ctx)
			if err == nil {
				m.mu.Lock()
				if m.closed {
					m.mu.Unlock()
					_ = next.Close() //nolint:errcheck // Cancellation cleanup cannot change the completed operation result.
					return nil
				}
				m.current = next
				close(m.changed)
				m.changed = make(chan struct{})
				m.mu.Unlock()
				backoff = initialBackoff
				break
			}
			delay, err := jitter(backoff)
			if err != nil {
				return err
			}
			timer := time.NewTimer(delay)
			select {
			case <-m.ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
			backoff *= 2
			if backoff > maximumBackoff {
				backoff = maximumBackoff
			}
		}
	}
}

func jitter(base time.Duration) (time.Duration, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(base)))
	if err != nil {
		return 0, err
	}
	return base/2 + time.Duration(n.Int64()), nil
}

func (m *Manager) currentSession(ctx context.Context) (*session.Session, error) {
	for {
		m.mu.Lock()
		current, changed, closed := m.current, m.changed, m.closed
		m.mu.Unlock()
		if closed {
			return nil, net.ErrClosed
		}
		select {
		case <-current.Done():
		default:
			return current, nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-m.ctx.Done():
			return nil, net.ErrClosed
		}
	}
}

// DialContext waits within the open budget and creates a new TCP stream.
func (m *Manager) DialContext(ctx context.Context, target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, m.limits.OpenTimeout)
	defer cancel()
	current, err := m.currentSession(ctx)
	if err != nil {
		return nil, err
	}
	return current.DialContext(ctx, target)
}

// Protocol returns the active transport, including the h2 reliability tradeoff.
func (m *Manager) Protocol() string { m.mu.Lock(); defer m.mu.Unlock(); return m.current.Protocol() }

// Close stops reconnection and joins the health worker and packet associations.
func (m *Manager) Close() error {
	m.once.Do(func() {
		m.cancel()
		m.mu.Lock()
		m.closed = true
		current := m.current
		packets := make([]*packetConn, 0, len(m.packets))
		for packet := range m.packets {
			packets = append(packets, packet)
		}
		m.mu.Unlock()
		m.closeErr = current.Close()
		for _, packet := range packets {
			m.closeErr = errors.Join(m.closeErr, packet.Close())
		}
		m.closeErr = errors.Join(m.closeErr, m.group.Wait())
	})
	return m.closeErr
}
