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

	"github.com/rityak/quri"
)

// Serve accepts at most 64 concurrent local clients. Canceling ctx closes the
// listener and active connections, including UDP associations.
func Serve(ctx context.Context, listener net.Listener, session *quri.Session) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	host, _, err := net.SplitHostPort(listener.Addr().String())
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("socks5: listener must use a loopback IP")
	}
	var mu sync.Mutex
	clients := make(map[net.Conn]struct{})
	var wg sync.WaitGroup
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
		case <-done:
		}
		listener.Close()
		mu.Lock()
		for c := range clients {
			c.Close()
		}
		mu.Unlock()
	}()
	defer func() { wg.Wait(); close(done); <-stopped }()
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
		if len(clients) >= 64 {
			mu.Unlock()
			c.Close()
			continue
		}
		clients[c] = struct{}{}
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Close()
			defer func() { mu.Lock(); delete(clients, c); mu.Unlock() }()
			serveConn(ctx, c, session)
		}()
	}
}

func serveConn(ctx context.Context, c net.Conn, session *quri.Session) {
	c.SetDeadline(time.Now().Add(5 * time.Second))
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
		c.Write([]byte{5, 255})
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
		reply(c, 8, nil)
		return
	}
	switch request[1] {
	case 1:
		dial, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		remote, err := session.DialContext(dial, address)
		if err != nil {
			code := byte(4)
			switch {
			case errors.Is(err, quri.ErrDenied):
				code = 2
			case errors.Is(err, syscall.ECONNREFUSED):
				code = 5
			case errors.Is(err, quri.ErrProtocol) || errors.Is(err, quri.ErrLimit) || errors.Is(err, quri.ErrDraining):
				code = 1
			}
			reply(c, code, nil)
			return
		}
		defer remote.Close()
		if reply(c, 0, nil) != nil {
			return
		}
		c.SetDeadline(time.Time{})
		quri.Relay(c, remote)
	case 3:
		serveUDP(ctx, c, session, address)
	default:
		reply(c, 7, nil)
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
			return "", quri.ErrProtocol
		}
		b := make([]byte, int(n[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		return "", quri.ErrProtocol
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
	port, err := strconv.Atoi(service)
	if err != nil || port < 0 || port > 65535 {
		return nil, quri.ErrProtocol
	}
	var b []byte
	ip := net.ParseIP(host)
	switch {
	case ip != nil && ip.To4() != nil:
		b = append([]byte{1}, ip.To4()...)
	case ip != nil:
		b = append([]byte{4}, ip.To16()...)
	case len(host) > 0 && len(host) <= 255:
		b = append([]byte{3, byte(len(host))}, host...)
	default:
		return nil, quri.ErrProtocol
	}
	return append(b, byte(port>>8), byte(port)), nil
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

func serveUDP(ctx context.Context, c net.Conn, session *quri.Session, requested string) {
	sourceHost, _, _ := net.SplitHostPort(c.RemoteAddr().String())
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
		reply(c, 2, nil)
		return
	}
	localHost, _, _ := net.SplitHostPort(c.LocalAddr().String())
	socket, err := net.ListenPacket("udp", net.JoinHostPort(localHost, "0"))
	if err != nil {
		reply(c, 1, nil)
		return
	}
	defer socket.Close()
	packet, err := session.ListenPacket(ctx)
	if err != nil {
		reply(c, 1, nil)
		return
	}
	defer packet.Close()
	if reply(c, 0, socket.LocalAddr()) != nil {
		return
	}
	c.SetDeadline(time.Time{})
	var peerMu sync.Mutex
	var peer net.Addr
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer packet.Close()
		defer socket.Close()
		defer c.Close()
		buf := make([]byte, 65535)
		for {
			n, addr, err := socket.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
				continue
			}
			remoteHost, remotePort, _ := net.SplitHostPort(addr.String())
			actualPort, _ := strconv.Atoi(remotePort)
			if !net.ParseIP(remoteHost).Equal(sourceIP) || (port != 0 && port != actualPort) {
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
			target, err := quri.UDPAddress(destination)
			if err != nil {
				continue
			}
			packet.WriteTo(buf[n-reader.Len():n], target)
		}
	}()
	go func() {
		defer wg.Done()
		defer c.Close()
		buf := make([]byte, 65535)
		for {
			n, addr, err := packet.ReadFrom(buf)
			if err != nil {
				return
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
			payload := append(append(make([]byte, 3, 3+len(header)+n), header...), buf[:n]...)
			socket.WriteTo(payload, destination)
		}
	}()
	io.Copy(io.Discard, c)
	socket.Close()
	packet.Close()
	wg.Wait()
}
