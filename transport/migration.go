package transport

import (
	"context"
	"errors"
	"fmt"
	"net"

	quic "github.com/metacubex/quic-go"
	"github.com/rityak/quri/config"
)

// ErrMigrationUnsupported identifies the reliable fallback, which reconnects
// instead of migrating an existing TCP connection.
var ErrMigrationUnsupported = errors.New("connection migration requires h3")

var errHealthResponse = errors.New("relay health check was not authenticated")

// Migrate validates a fresh local UDP socket before switching the same QUIC
// connection. The remote endpoint, authentication and existing flows are kept.
// A failed candidate before Switch leaves the old path usable. Failure after
// Switch closes the connection so the manager can reconnect explicitly.
func (c *Conn) Migrate(ctx context.Context) (result error) {
	if c.quic == nil {
		return ErrMigrationUnsupported
	}
	c.pathMu.Lock()
	defer c.pathMu.Unlock()
	if c.ctx.Err() != nil {
		return net.ErrClosed
	}
	ctx, cancel := context.WithTimeout(ctx, c.limits.OpenTimeout)
	defer cancel()
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	var socket net.PacketConn
	var err error
	if c.listenPacket != nil {
		socket, err = c.listenPacket(ctx, c.endpoint)
	} else {
		network := "udp6"
		if c.endpoint.Addr().Is4() {
			network = "udp4"
		}
		socket, err = net.ListenPacket(network, "")
	}
	if err != nil {
		return err
	}
	next := &quic.Transport{Conn: socket, ConnectionIDLength: config.DefaultConnectionIDLength}
	next.SetSingleUse(true)
	committed := false
	defer func() {
		if committed {
			return
		}
		if c.ctx.Err() == nil {
			cleanupCtx, stop := context.WithTimeout(c.ctx, c.limits.OpenTimeout)
			err := c.quic.RetirePathTransport(cleanupCtx, next)
			stop()
			if err != nil {
				c.cancel()
				result = errors.Join(result, err, c.quic.CloseWithError(0x102, ""))
			}
		}
		result = errors.Join(result, next.Close(), socket.Close())
	}()
	path, err := c.quic.AddPath(next)
	if err != nil {
		return err
	}
	if err := path.Probe(ctx); err != nil {
		return fmt.Errorf("validate migration path: %w", err)
	}
	if err := path.Switch(); err != nil {
		return fmt.Errorf("switch migration path: %w", err)
	}
	// This round trip both wakes the sender and proves the switched path can
	// carry authenticated application traffic before the old socket is retired.
	if err := c.Probe(ctx); err != nil {
		c.cancel()
		return errors.Join(fmt.Errorf("verify migrated HTTP connection: %w", err), c.quic.CloseWithError(0x102, ""))
	}
	if err := c.quic.RetirePathTransport(ctx, c.transport); err != nil {
		c.cancel()
		return errors.Join(fmt.Errorf("retire previous migration path: %w", err), c.quic.CloseWithError(0x102, ""))
	}
	previous, previousSocket := c.transport, c.socket
	c.transport, c.socket = next, socket
	committed = true
	return errors.Join(previous.Close(), previousSocket.Close())
}
