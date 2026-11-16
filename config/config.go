// Package config defines shared resource and timing limits.
package config

import (
	"errors"
	"time"
)

// Defaults apply to both HTTP transports.
const (
	// ControlPath is shared by the authenticated configuration and health endpoints.
	ControlPath               = "/api/session"
	DefaultHandshakeTimeout   = 5 * time.Second
	DefaultOpenTimeout        = 5 * time.Second
	DefaultIdleTimeout        = 60 * time.Second
	DefaultFallbackDelay      = 250 * time.Millisecond
	DefaultMaxConnections     = 64
	DefaultMaxStreams         = 64
	DefaultMaxUDPTargets      = 32
	DefaultMaxDatagram        = 1150
	DefaultConnectionIDLength = 8
	DefaultMaxControl         = 1 << 20
	DefaultQueueSize          = 16
	DefaultKeepAliveMin       = 10 * time.Second
	DefaultKeepAliveMax       = 25 * time.Second
	DefaultPathProbeCooldown  = time.Second
	DefaultDatagramLifetime   = 100 * time.Millisecond
)

// Config bounds independently owned connections, streams and UDP queues.
// Call WithDefaults before Validate when reading optional user settings.
type Config struct {
	HandshakeTimeout      time.Duration `json:"handshake_timeout_ns"`
	OpenTimeout           time.Duration `json:"open_timeout_ns"`
	IdleTimeout           time.Duration `json:"idle_timeout_ns"`
	ConnectionIdleTimeout time.Duration `json:"connection_idle_timeout_ns"`
	KeepAliveMin          time.Duration `json:"keepalive_min_ns"`
	KeepAliveMax          time.Duration `json:"keepalive_max_ns"`
	FallbackDelay         time.Duration `json:"fallback_delay_ns"`
	MaxConnections        int           `json:"max_connections"`
	MaxStreams            int           `json:"max_streams"`
	MaxUDPTargets         int           `json:"max_udp_targets"`
	MaxDatagram           int           `json:"max_datagram"`
	MaxControl            int           `json:"max_control"`
	QueueSize             int           `json:"queue_size"`
}

// WithDefaults returns a value snapshot with zero fields replaced.
func (c Config) WithDefaults() Config {
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if c.OpenTimeout == 0 {
		c.OpenTimeout = DefaultOpenTimeout
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = DefaultIdleTimeout
	}
	if c.ConnectionIdleTimeout == 0 {
		c.ConnectionIdleTimeout = DefaultIdleTimeout
	}
	if c.KeepAliveMin == 0 {
		c.KeepAliveMin = DefaultKeepAliveMin
	}
	if c.KeepAliveMax == 0 {
		c.KeepAliveMax = DefaultKeepAliveMax
	}
	if c.FallbackDelay == 0 {
		c.FallbackDelay = DefaultFallbackDelay
	}
	if c.MaxConnections == 0 {
		c.MaxConnections = DefaultMaxConnections
	}
	if c.MaxStreams == 0 {
		c.MaxStreams = DefaultMaxStreams
	}
	if c.MaxUDPTargets == 0 {
		c.MaxUDPTargets = DefaultMaxUDPTargets
	}
	if c.MaxDatagram == 0 {
		c.MaxDatagram = DefaultMaxDatagram
	}
	if c.MaxControl == 0 {
		c.MaxControl = DefaultMaxControl
	}
	if c.QueueSize == 0 {
		c.QueueSize = DefaultQueueSize
	}
	return c
}

// Validate rejects unbounded resources and inconsistent timing settings.
func (c Config) Validate() error {
	if c.KeepAliveMin <= 0 || c.KeepAliveMax < c.KeepAliveMin || c.ConnectionIdleTimeout <= c.KeepAliveMax || c.OpenTimeout >= c.ConnectionIdleTimeout-c.KeepAliveMax {
		return errors.New("keepalive and probe budgets must fit the connection idle timeout")
	}
	if c.HandshakeTimeout <= 0 || c.OpenTimeout <= 0 || c.IdleTimeout <= 0 || c.FallbackDelay <= 0 || c.FallbackDelay >= c.HandshakeTimeout {
		return errors.New("invalid connection timing limits")
	}
	if c.MaxConnections < 1 || c.MaxConnections > 1024 || c.MaxStreams < 1 || c.MaxStreams > 1024 || c.MaxUDPTargets < 1 || c.MaxUDPTargets > 256 || c.QueueSize < 1 || c.QueueSize > 256 {
		return errors.New("invalid connection resource limits")
	}
	if c.MaxDatagram < 1 || c.MaxDatagram > 65507 || c.MaxControl < 1 || c.MaxControl > DefaultMaxControl {
		return errors.New("invalid message size limit")
	}
	return nil
}
