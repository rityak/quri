package transport

import (
	"strconv"

	"github.com/rityak/quri/route"
)

// TunnelError exposes only a peer HTTP status, never an outbound configuration.
type TunnelError struct{ Status int }

// Error describes a rejected tunnel without reflecting peer response content.
func (e *TunnelError) Error() string { return "relay rejected tunnel: HTTP " + strconv.Itoa(e.Status) }

// Is preserves routing categories for callers such as SOCKS5.
func (e *TunnelError) Is(target error) bool {
	switch e.Status {
	case 400:
		return target == route.ErrProtocol
	case 403:
		return target == route.ErrDenied
	case 429, 503:
		return target == route.ErrLimit
	}
	return false
}
