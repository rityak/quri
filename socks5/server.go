// Package socks5 provides a loopback SOCKS5 entry point for an quri session.
package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/rityak/quri/config"
	"github.com/rityak/quri/route"
	"golang.org/x/sync/errgroup"
)

// Client opens flows without exposing transport or session implementation details.
type Client interface {
	DialContext(context.Context, string) (net.Conn, error)
	ListenPacket(context.Context) (net.PacketConn, error)
}

// Serve accepts at most 64 loopback clients and closes all flows on cancellation.
func Serve(ctx context.Context, listener net.Listener, session Client) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	host, _, err := net.SplitHostPort(listener.Addr().String())
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("socks5: listener must use a loopback IP")
	}
	var mu sync.Mutex
	clients := make(map[net.Conn]struct{})
	var workers errgroup.Group
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(stopped)
		closeOwned(listener)
		mu.Lock()
		for c := range clients {
			closeOwned(c)
		}
		mu.Unlock()
	})
	defer func() {
		_ = workers.Wait() //nolint:errcheck // Client workers always return nil after releasing their owned flow.
		if !stop() {
			<-stopped
		}
	}() //nolint:errcheck // Client workers return nil after releasing their owned flow.
	for {
		c, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			cancel()
			return err
		}
		mu.Lock()
		if len(clients) >= config.DefaultMaxStreams {
			mu.Unlock()
			closeOwned(c)
			continue
		}
		clients[c] = struct{}{}
		mu.Unlock()
		workers.Go(func() error {
			defer closeOwned(c)
			defer func() { mu.Lock(); delete(clients, c); mu.Unlock() }()
			serveConn(ctx, c, session)
			return nil
		})
	}
}

func serveConn(ctx context.Context, c net.Conn, session Client) {
	if err := c.SetDeadline(time.Now().Add(config.DefaultOpenTimeout)); err != nil {
		return
	}
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 5 || h[1] == 0 {
		return
	}
	methods := make([]byte, int(h[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	supported := false
	for _, method := range methods {
		if method == 0 {
			supported = true
		}
	}
	if !supported {
		_, _ = c.Write([]byte{5, 255}) //nolint:errcheck // A rejected SOCKS handshake is closed regardless of peer write errors.
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	var request [3]byte
	if _, err := io.ReadFull(c, request[:]); err != nil || request[0] != 5 || request[2] != 0 {
		return
	}
	address, err := readAddress(c)
	if err != nil {
		_ = reply(c, 8, nil) //nolint:errcheck // The handler returns after this final error reply.
		return
	}
	switch request[1] {
	case 1:
		dial, cancel := context.WithTimeout(ctx, config.DefaultOpenTimeout)
		defer cancel()
		remote, err := session.DialContext(dial, address)
		if err != nil {
			code := byte(4)
			switch {
			case errors.Is(err, route.ErrDenied):
				code = 2
			case errors.Is(err, syscall.ECONNREFUSED):
				code = 5
			case errors.Is(err, route.ErrProtocol) || errors.Is(err, route.ErrLimit):
				code = 1
			}
			_ = reply(c, code, nil) //nolint:errcheck // The handler returns after this final error reply.
			return
		}
		defer closeOwned(remote)
		if reply(c, 0, nil) != nil {
			return
		}
		if err := c.SetDeadline(time.Time{}); err != nil {
			return
		}
		_ = route.Relay(c, remote) //nolint:errcheck // Relay closes both endpoints; no SOCKS reply is valid after CONNECT succeeds.
	case 3:
		serveUDP(ctx, c, session, address)
	default:
		_ = reply(c, 7, nil) //nolint:errcheck // The handler returns after this final error reply.
	}
}

func readAddress(r io.Reader) (string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", err
	}
	var host string
	switch atyp[0] {
	case 1, 4:
		size := 4
		if atyp[0] == 4 {
			size = 16
		}
		b := make([]byte, size)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil || n[0] == 0 {
			return "", route.ErrProtocol
		}
		b := make([]byte, int(n[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		return "", route.ErrProtocol
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

func encodeAddress(address string) ([]byte, error) {
	host, service, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(service, 10, 16)
	if err != nil {
		return nil, route.ErrProtocol
	}
	var b []byte
	ip := net.ParseIP(host)
	switch {
	case ip != nil && ip.To4() != nil:
		b = append([]byte{1}, ip.To4()...)
	case ip != nil:
		b = append([]byte{4}, ip.To16()...)
	case len(host) > 0 && len(host) <= 255:
		b = append([]byte{3, byte(len(host))}, host...) //nolint:gosec // The case bounds the hostname length to 255.
	default:
		return nil, route.ErrProtocol
	}
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}

func closeOwned(c io.Closer) {
	_ = c.Close() //nolint:errcheck // The owner is already terminating this endpoint; there is no recoverable close action.
}

func reply(w io.Writer, code byte, addr net.Addr) error {
	address := "0.0.0.0:0"
	if addr != nil {
		address = addr.String()
	}
	b, err := encodeAddress(address)
	if err != nil {
		return err
	}
	_, err = w.Write(append([]byte{5, code, 0}, b...))
	return err
}

func serveUDP(ctx context.Context, c net.Conn, client Client, requested string) {
	sourceHost, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return
	}
	sourceIP := net.ParseIP(sourceHost)
	host, service, err := net.SplitHostPort(requested)
	if err != nil {
		return
	}
	port, err := strconv.Atoi(service)
	if err != nil {
		return
	}
	if requestedIP := net.ParseIP(host); requestedIP == nil || (!requestedIP.IsUnspecified() && !requestedIP.Equal(sourceIP)) {
		_ = reply(c, 2, nil) //nolint:errcheck // The rejected association is closed after its final reply.
		return
	}
	localHost, _, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil {
		return
	}
	socket, err := net.ListenPacket("udp", net.JoinHostPort(localHost, "0"))
	if err != nil {
		_ = reply(c, 1, nil) //nolint:errcheck // The rejected association closes after its final reply.
		return
	} //nolint:errcheck // The rejected association is closed after its final reply.
	defer closeOwned(socket)
	packet, err := client.ListenPacket(ctx)
	if err != nil {
		_ = reply(c, 1, nil) //nolint:errcheck // The rejected association closes after its final reply.
		return
	} //nolint:errcheck // The rejected association is closed after its final reply.
	defer closeOwned(packet)
	if err := reply(c, 0, socket.LocalAddr()); err != nil {
		return
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		return
	}
	var peerMu sync.Mutex
	var peer net.Addr
	ownedCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	workers, runCtx := errgroup.WithContext(ownedCtx)
	stopped := make(chan struct{})
	stop := context.AfterFunc(runCtx, func() { closeOwned(socket); closeOwned(packet); closeOwned(c); close(stopped) })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	workers.Go(func() error {
		buf := make([]byte, 65535)
		for {
			n, addr, err := socket.ReadFrom(buf)
			if err != nil {
				return err
			}
			if n < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
				continue
			}
			remoteHost, remotePort, err := net.SplitHostPort(addr.String())
			if err != nil {
				continue
			}
			actualPort, err := strconv.Atoi(remotePort)
			if err != nil || !net.ParseIP(remoteHost).Equal(sourceIP) || (port != 0 && port != actualPort) {
				continue
			}
			peerMu.Lock()
			if peer == nil {
				peer = addr
			}
			matched := peer.String() == addr.String()
			peerMu.Unlock()
			if !matched {
				continue
			}
			reader := bytes.NewReader(buf[3:n])
			destination, err := readAddress(reader)
			if err != nil {
				continue
			}
			target, err := route.UDPAddress(destination)
			if err != nil {
				continue
			}
			if _, err := packet.WriteTo(buf[n-reader.Len():n], target); err != nil {
				continue
			}
		}
	})
	workers.Go(func() error {
		buf := make([]byte, 65535)
		payload := make([]byte, 3, 65535+260)
		for {
			n, addr, err := packet.ReadFrom(buf)
			if err != nil {
				return err
			}
			header, err := encodeAddress(addr.String())
			if err != nil {
				continue
			}
			peerMu.Lock()
			destination := peer
			peerMu.Unlock()
			if destination == nil {
				continue
			}
			data := append(append(payload[:3], header...), buf[:n]...)
			if _, err := socket.WriteTo(data, destination); err != nil {
				return err
			}
		}
	})
	_, _ = io.Copy(io.Discard, c) //nolint:errcheck // Closing the SOCKS control stream terminates its UDP association.
	cancel()
	_ = workers.Wait() //nolint:errcheck // Worker failures close the control stream; the successful SOCKS reply cannot be replaced.
}

// ServeClient is an alias for Serve.
func ServeClient(ctx context.Context, listener net.Listener, client Client) error {
	return Serve(ctx, listener, client)
}
