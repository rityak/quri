package quri

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestWireVectors(t *testing.T) {
	var b bytes.Buffer
	if err := writeBlob(&b, []byte("abc"), 3); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(b.Bytes()) != "00000003616263" {
		t.Fatal("blob wire format changed")
	}
	raw, _ := hex.DecodeString("010000000000000007000000027b7d")
	f, err := readFrame(bytes.NewReader(raw), func(int64) bool { return true })
	if err != nil || f.kind != 1 || f.id != 7 || string(f.data) != "{}" {
		t.Fatal(f, err)
	}
	if _, err := readBlob(bytes.NewReader([]byte{255, 255, 255, 255}), maxControl); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
}

func fragment(association, message uint64, total, offset int, index, count byte, address string, data []byte) []byte {
	b := make([]byte, 24+len(address)+len(data))
	binary.BigEndian.PutUint64(b[:8], association)
	binary.BigEndian.PutUint64(b[8:16], message)
	binary.BigEndian.PutUint16(b[16:18], uint16(total))
	binary.BigEndian.PutUint16(b[18:20], uint16(offset))
	binary.BigEndian.PutUint16(b[20:22], uint16(len(address)))
	b[22] = index
	b[23] = count
	copy(b[24:], address)
	copy(b[24+len(address):], data)
	return b
}
func assemblySession() (*Session, *PacketConn) {
	s := &Session{packets: make(map[uint64]*PacketConn), globalBudget: new(bufferBudget)}
	s.assembly.entries = make(map[messageKey]*assembly)
	p := &PacketConn{session: s, queue: make(chan datagram, 16), done: make(chan struct{}), changed: make(chan struct{})}
	s.packets[4] = p
	return s, p
}
func clearAssembly(s *Session, p *PacketConn) {
	s.assembly.clear(s)
	for {
		select {
		case d := <-p.queue:
			s.releaseDatagramBytes(int64(len(d.data)))
		default:
			return
		}
	}
}

func TestReassemblyOrderDuplicatesAndExpiry(t *testing.T) {
	s, p := assemblySession()
	defer clearAssembly(s, p)
	now := time.Now()
	second := fragment(4, 1, 6, 3, 1, 2, "", []byte("def"))
	first := fragment(4, 1, 6, 0, 0, 2, "127.0.0.1:9", []byte("abc"))
	s.assembly.accept(s, second, now)
	s.assembly.accept(s, second, now)
	s.assembly.accept(s, first, now)
	select {
	case got := <-p.queue:
		if string(got.data) != "abcdef" || got.address != "127.0.0.1:9" {
			t.Fatal(got)
		}
		s.releaseDatagramBytes(int64(len(got.data)))
	default:
		t.Fatal("reordered datagram not assembled")
	}
	s.assembly.accept(s, first, now)
	s.assembly.accept(s, second, now)
	if len(p.queue) != 0 {
		t.Fatal("duplicate delivery")
	}
	s.assembly.accept(s, fragment(4, 2, 6, 0, 0, 2, "127.0.0.1:9", []byte("abc")), now)
	s.assembly.expire(s, now.Add(301*time.Millisecond))
	if len(s.assembly.entries) != 0 || s.localBudget.Load() != 0 {
		t.Fatal("incomplete message leaked")
	}
	s.assembly.accept(s, fragment(4, 3, 6, 0, 0, 2, "127.0.0.1:9", []byte("abc")), now)
	s.assembly.accept(s, fragment(4, 3, 6, 2, 1, 2, "", []byte("def")), now)
	if len(p.queue) != 0 || len(s.assembly.entries) != 0 {
		t.Fatal("overlapping fragments accepted")
	}
}

func TestReassemblyCapsAndVector(t *testing.T) {
	s, p := assemblySession()
	defer clearAssembly(s, p)
	now := time.Now()
	raw, _ := hex.DecodeString("0000000000000004000000000000000100030000000b00013132372e302e302e313a39616263")
	s.assembly.accept(s, raw, now)
	select {
	case d := <-p.queue:
		if string(d.data) != "abc" {
			t.Fatal(d)
		}
		s.releaseDatagramBytes(3)
	default:
		t.Fatal("independent vector rejected")
	}
	for id := uint64(2); id < 40; id++ {
		s.assembly.accept(s, fragment(4, id, maxPayload, 0, 0, 64, "127.0.0.1:9", []byte("x")), now)
	}
	if s.assembly.bytes > 1<<20 || len(s.assembly.entries) > 32 || s.stats.overflow.Load() == 0 {
		t.Fatal("reassembly limits not enforced")
	}
}

func FuzzFraming(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 'x'})
	f.Add([]byte{255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, b []byte) {
		readBlob(bytes.NewReader(b), maxOpen)
		readFrame(bytes.NewReader(b), func(int64) bool { return true })
	})
}
func FuzzDatagram(f *testing.F) {
	f.Add(fragment(4, 1, 3, 0, 0, 1, "127.0.0.1:9", []byte("abc")))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65535 {
			return
		}
		s, p := assemblySession()
		s.assembly.accept(s, b, time.Now())
		clearAssembly(s, p)
		if s.localBudget.Load() != 0 {
			t.Fatal("unbalanced byte budget")
		}
	})
}

type blackholePacket struct {
	net.PacketConn
	drop atomic.Bool
}

func (p *blackholePacket) WriteTo(b []byte, addr net.Addr) (int, error) {
	if p.drop.Load() {
		return len(b), nil
	}
	return p.PacketConn.WriteTo(b, addr)
}
func TestCanceledOpenAndCleanup(t *testing.T) {
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	loss := &blackholePacket{PacketConn: socket}
	s, _ := testPair(t, loss)
	loss.drop.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	started := time.Now()
	stream, err := s.DialContext(ctx, "127.0.0.1:9")
	if stream != nil {
		stream.Close()
	}
	if !errors.Is(err, context.Canceled) || time.Since(started) > time.Second {
		t.Fatalf("canceled open: %v after %s", err, time.Since(started))
	}
	s.Close()
	wait, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err = s.Wait(wait); err != nil {
		t.Fatal(err)
	}
	if s.localBudget.Load() != 0 {
		t.Fatal("buffers leaked", s.localBudget.Load())
	}
}

func TestControlReplayAndConflict(t *testing.T) {
	s, _ := testPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req := Request{Namespace: "echo", Version: 1, Payload: []byte("once")}
	if _, err := s.Message(ctx, req); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.nextID--
	s.mu.Unlock()
	if b, err := s.Message(ctx, req); err != nil || string(b) != "once" {
		t.Fatal(string(b), err)
	}
	s.mu.Lock()
	s.nextID--
	s.mu.Unlock()
	req.Payload = []byte("conflict")
	if _, err := s.Message(ctx, req); err == nil {
		t.Fatal("conflicting request ID accepted")
	}
}

func TestControlDuringBulkTransfer(t *testing.T) {
	s, _ := testPair(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(io.Discard, c) }()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var streams []*Stream
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		st, err := s.DialContext(ctx, listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		streams = append(streams, st)
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 32<<10)
			for {
				if _, err := st.Write(buf); err != nil {
					return
				}
			}
		}()
	}
	udpTarget, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpTarget.Close()
	go func() {
		buffer := make([]byte, 2048)
		for {
			if _, _, err := udpTarget.ReadFrom(buffer); err != nil {
				return
			}
		}
	}()
	udp, err := s.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	udpDone := make(chan struct{})
	firstSent := make(chan struct{})
	go func() {
		defer close(udpDone)
		payload := make([]byte, 1000)
		first := true
		for {
			if _, err := udp.WriteTo(payload, udpTarget.LocalAddr()); err != nil {
				return
			}
			if first {
				close(firstSent)
				first = false
			}
		}
	}()
	defer func() { udp.Close(); <-udpDone }()
	select {
	case <-firstSent:
	case <-ctx.Done():
		t.Fatal("UDP producer did not start")
	}
	latencies := make([]time.Duration, 10)
	for i := range latencies {
		started := time.Now()
		if _, err := s.Message(ctx, Request{Namespace: "echo", Version: 1, Payload: []byte("control")}); err != nil {
			t.Fatal(err)
		}
		latencies[i] = time.Since(started)
	}
	for _, st := range streams {
		st.Close()
	}
	wg.Wait()
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	t.Logf("8 bulk streams + UDP, control p50=%s p95=%s max=%s", latencies[4], latencies[9], latencies[9])
	if latencies[9] > time.Second {
		t.Fatal("control starved")
	}
}

func TestPacketReadDeadlineChanges(t *testing.T) {
	s, _ := testPair(t)
	p, err := s.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	done := make(chan error, 1)
	go func() { _, _, err := p.ReadFrom(make([]byte, 1)); done <- err }()
	p.SetReadDeadline(time.Now().Add(time.Millisecond))
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not interrupt read")
	}
}

func TestServerInitiatedMessage(t *testing.T) {
	_, server := testPair(t)
	server.mu.Lock()
	var remote *Session
	for s := range server.sessions {
		remote = s
	}
	server.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	b, err := remote.Message(ctx, Request{Namespace: "core", Version: 1, Payload: []byte("server message")})
	if err != nil || string(b) != "server message" {
		t.Fatal(string(b), err)
	}
}

func TestIPv6AndDomainDestinations(t *testing.T) {
	s, _ := testPairOn(t, "udp6", "[::1]:0")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	target, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		c, err := target.Accept()
		if err == nil {
			defer c.Close()
			c.Write([]byte("ipv6"))
		}
	}()
	_, port, _ := net.SplitHostPort(target.Addr().String())
	st, err := s.DialContext(ctx, net.JoinHostPort("localhost", port))
	if err != nil {
		t.Fatal(err)
	}
	st.SetDeadline(time.Now().Add(time.Second))
	b, err := io.ReadAll(st)
	st.Close()
	if err != nil || string(b) != "ipv6" {
		t.Fatal(string(b), err)
	}
	udp, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 1024)
		n, a, err := udp.ReadFrom(b)
		if err == nil {
			udp.WriteTo(b[:n], a)
		}
	}()
	p, err := s.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.SetDeadline(time.Now().Add(time.Second))
	if _, err = p.WriteTo([]byte("udp6"), udp.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, _, err := p.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "udp6" {
		t.Fatal(string(buf[:n]), err)
	}
}

func TestPacketWriteDeadlineChanges(t *testing.T) {
	s, _ := testPair(t)
	p, err := s.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	<-p.writeGate
	defer func() { p.writeGate <- struct{}{} }()
	done := make(chan error, 1)
	go func() { _, err := p.WriteTo([]byte("blocked"), packetAddr("127.0.0.1:9")); done <- err }()
	p.SetWriteDeadline(time.Now())
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("write deadline did not wake queued writer")
	}
}

func TestReplayWindowDoesNotLimitSession(t *testing.T) {
	s, _ := testPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := 0; i < maxCachedReplies+3; i++ {
		if _, err := s.Message(ctx, Request{Namespace: "echo", Version: 1}); err != nil {
			t.Fatal(err)
		}
	}
	s.mu.Lock()
	last := s.nextID
	s.nextID = 0
	s.mu.Unlock()
	if _, err := s.request(ctx, configureKind, Request{Namespace: "direct", Version: 1, Payload: []byte("{}")}); err == nil {
		t.Fatal("evicted request executed again")
	}
	s.mu.Lock()
	s.nextID = last
	s.mu.Unlock()
	if s.conn.Context().Err() != nil {
		t.Fatal("stale request aborted traffic")
	}
	if err := s.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

type impairedPacket struct {
	net.PacketConn
	mu       sync.Mutex
	count    int
	held     []byte
	heldAddr net.Addr
	drops    atomic.Int64
}

func (p *impairedPacket) WriteTo(b []byte, a net.Addr) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.count++
	if len(b) > 1200 || p.count%13 == 0 {
		p.drops.Add(1)
		return len(b), nil
	}
	if p.count%19 == 0 && p.held == nil {
		p.held = append([]byte(nil), b...)
		p.heldAddr = a
		return len(b), nil
	}
	n, err := p.PacketConn.WriteTo(b, a)
	if p.held != nil {
		p.PacketConn.WriteTo(p.held, p.heldAddr)
		p.held = nil
	}
	if p.count%17 == 0 {
		p.PacketConn.WriteTo(b, a)
	}
	return n, err
}
func (p *impairedPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, a, err := p.PacketConn.ReadFrom(b)
		if err != nil || n <= 1200 {
			return n, a, err
		}
		p.drops.Add(1)
	}
}

func TestTCPRecoveryWithLossReorderingAndMTU(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	network := &impairedPacket{PacketConn: pc}
	s, _ := testPair(t, network)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		c, err := target.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := s.DialContext(ctx, target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.SetDeadline(time.Now().Add(10 * time.Second))
	payload := bytes.Repeat([]byte("integrity"), 16384)
	done := make(chan error, 1)
	go func() {
		err := writeAll(st, payload)
		if err == nil {
			err = st.CloseWrite()
		}
		done <- err
	}()
	reply, err := io.ReadAll(st)
	if err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, payload) || network.drops.Load() == 0 {
		t.Fatal("recovery/MTU profile did not exercise intact traffic and loss")
	}
}

func TestConnectionRefusalRemainsDistinctFromPolicy(t *testing.T) {
	s, _ := testPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := target.Addr().String()
	target.Close()
	if _, err = s.DialContext(ctx, address); !errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, ErrDenied) {
		t.Fatalf("refusal classification: %v", err)
	}
	if _, err = s.DialContext(ctx, "192.0.2.1:80"); !errors.Is(err, ErrDenied) {
		t.Fatalf("policy classification: %v", err)
	}
}

func TestTCPReadTimeoutDoesNotCompleteFlow(t *testing.T) {
	s, _ := testPair(t)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	respond := make(chan struct{}, 1)
	defer close(respond)
	go func() {
		c, err := target.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.ReadAll(c)
		<-respond
		c.Write([]byte("after timeout"))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	st, err := s.DialContext(ctx, target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.CloseWrite()
	st.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
	if _, err = st.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	s.mu.Lock()
	_, active := s.streams[st]
	s.mu.Unlock()
	if !active {
		t.Fatal("temporary read timeout completed a live flow")
	}
	st.SetReadDeadline(time.Now().Add(time.Second))
	respond <- struct{}{}
	data, err := io.ReadAll(st)
	if err != nil || string(data) != "after timeout" {
		t.Fatal(string(data), err)
	}
}

func TestOneWayUDPRemainsActive(t *testing.T) {
	s, server := testPair(t)
	server.mu.Lock()
	var remote *Session
	for candidate := range server.sessions {
		remote = candidate
	}
	server.mu.Unlock()
	remote.mu.Lock()
	remote.udpIdleTimeout = 100 * time.Millisecond
	remote.mu.Unlock()
	target, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		b := make([]byte, 128)
		for {
			n, a, err := target.ReadFrom(b)
			if err != nil {
				return
			}
			if string(b[:n]) == "echo" {
				target.WriteTo(b[:n], a)
			}
		}
	}()
	p, err := s.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for i := 0; i < 16; i++ {
		if _, err = p.WriteTo([]byte("one-way"), target.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	p.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = p.WriteTo([]byte("echo"), target.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 128)
	n, _, err := p.ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != "echo" {
		t.Fatal("active one-way association expired", err)
	}
}
