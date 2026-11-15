package quri

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rityak/quri/internal/testcert"
)

func TestControlMemoryHeadroom(t *testing.T) {
	s, _ := testPair(t)
	const data = 8 << 20
	if !s.reserveDatagramBytes(data) || s.reserveDatagramBytes(1) {
		t.Fatal("session UDP ceiling")
	}
	defer s.releaseDatagramBytes(data)
	payload := bytes.Repeat([]byte{0xff}, maxApplication)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reply, err := s.Message(ctx, Request{Namespace: "echo", Version: 1, Payload: payload})
	if err != nil || !bytes.Equal(reply, payload) {
		t.Fatalf("maximum control request at UDP ceiling: %v, bytes=%d", err, len(reply))
	}
	global := new(bufferBudget)
	var sessions []*Session
	for i := 0; i < 12; i++ {
		session := &Session{globalBudget: global}
		if !session.reserveDatagramBytes(data) {
			t.Fatal("unexpected global rejection", i)
		}
		sessions = append(sessions, session)
	}
	extra := &Session{globalBudget: global}
	if extra.reserveDatagramBytes(1) || !extra.reserveBytes(maxControl) {
		t.Fatal("global control headroom exhausted by UDP")
	}
	extra.releaseBytes(maxControl)
	for _, session := range sessions {
		session.releaseDatagramBytes(data)
	}
	if global.total.Load() != 0 || global.data.Load() != 0 || extra.localBudget.Load() != 0 {
		t.Fatal("unbalanced global budget")
	}
}

func TestControlFrameProgressDeadline(t *testing.T) {
	s, _ := testPair(t)
	if _, err := s.control.Write([]byte{applicationKind}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	if err := s.Wait(ctx); err != nil {
		t.Fatal("partial control header kept session alive", err)
	}
}

func TestCanceledControlWriterAdmission(t *testing.T) {
	s, _ := testPair(t)
	<-s.writeGate
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := s.Message(ctx, Request{Namespace: "echo", Version: 1})
	s.writeGate <- struct{}{}
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatal("control writer admission ignored cancellation", err)
	}
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if _, err := s.Message(ctx, Request{Namespace: "echo", Version: 1}); err != nil {
		t.Fatal("admission cancellation damaged session", err)
	}
	if _, err := UDPAddress("bad\xff.example:53"); !errors.Is(err, ErrProtocol) {
		t.Fatal("invalid endpoint UTF-8 accepted", err)
	}
}

func TestControlRejectsInvalidUTF8(t *testing.T) {
	s, _ := testPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.sendFrame(ctx, frame{kind: applicationKind, id: 2, data: []byte{'"', 0xff, '"'}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Wait(ctx); err != nil {
		t.Fatal("invalid UTF-8 did not close the session", err)
	}
}

func tcpSink(t testing.TB) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return l
}

func TestActiveFlowLimitsAndForcedDrain(t *testing.T) {
	s, srv := testPair(t)
	l := tcpSink(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for i := 0; i < maxStreams; i++ {
		if _, err := s.DialContext(ctx, l.Addr().String()); err != nil {
			t.Fatalf("TCP %d: %v", i, err)
		}
	}
	if _, err := s.DialContext(ctx, l.Addr().String()); !errors.Is(err, ErrLimit) {
		t.Fatal("TCP ceiling", err)
	}
	for i := 0; i < maxAssociations; i++ {
		if _, err := s.ListenPacket(ctx); err != nil {
			t.Fatalf("UDP %d: %v", i, err)
		}
	}
	if _, err := s.ListenPacket(ctx); !errors.Is(err, ErrLimit) {
		t.Fatal("UDP ceiling", err)
	}
	if _, err := s.Message(ctx, Request{Namespace: "echo", Version: 1}); err != nil {
		t.Fatal("control at flow ceiling", err)
	}
	drain, stop := context.WithTimeout(ctx, 30*time.Millisecond)
	defer stop()
	if err := srv.Shutdown(drain); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("forced drain", err)
	}
	if err := s.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if s.localBudget.Load() != 0 || srv.budget.total.Load() != 0 || srv.budget.data.Load() != 0 {
		t.Fatal("retained buffers after drain")
	}
}

func TestServerRestartRequiresNewConfiguration(t *testing.T) {
	serverTLS, clientTLS := testcert.TLS(t)
	token := strings.Repeat("restart-secret-", 4)
	auth, err := TokenAuthenticator(map[Principal]string{"test": token})
	if err != nil {
		t.Fatal(err)
	}
	var applied atomic.Int64
	config := ServerConfig{TLS: serverTLS, Authenticate: auth,
		Configure: func(context.Context, Principal, Request) (Route, error) {
			applied.Add(1)
			return NewDirectRoute(DirectPolicy{Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
		}, Application: func(_ context.Context, _ Principal, r Request) ([]byte, error) { return r.Payload, nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	address := "127.0.0.1:0"
	var old *Session
	for generation := 1; generation <= 2; generation++ {
		pc, err := net.ListenPacket("udp", address)
		if err != nil {
			t.Fatal(err)
		}
		srv, err := Listen(pc, config)
		if err != nil {
			pc.Close()
			t.Fatal(err)
		}
		address = srv.Addr().String()
		go srv.Serve(ctx)
		s, err := Dial(ctx, address, ClientConfig{TLS: clientTLS, Token: token, Configuration: Request{Namespace: "direct", Version: 1}})
		if err != nil {
			srv.Shutdown(ctx)
			t.Fatal(err)
		}
		if applied.Load() != int64(generation) {
			t.Fatal("configuration was not applied once per new session", applied.Load())
		}
		if old != nil {
			if _, err := old.Message(ctx, Request{Namespace: "echo", Version: 1}); !errors.Is(err, net.ErrClosed) {
				t.Fatal("old session survived restart", err)
			}
		}
		if err := srv.Shutdown(ctx); err != nil {
			t.Fatal(err)
		}
		if err := s.Wait(ctx); err != nil {
			t.Fatal(err)
		}
		old = s
	}
}

// TestReadinessSoak is opt-in because it opens 64 real authenticated transports.
func TestReadinessSoak(t *testing.T) {
	value := os.Getenv("QURI_SOAK")
	if value == "" {
		t.Skip("set QURI_SOAK to a duration, e.g. 60s")
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration < time.Second {
		t.Fatal("invalid QURI_SOAK duration")
	}
	serverTLS, clientTLS := testcert.TLS(t)
	tokens := make(map[Principal]string)
	for i := 0; i < 16; i++ {
		tokens[Principal(fmt.Sprint(i))] = strings.Repeat(fmt.Sprintf("%02d", i), 24)
	}
	auth, err := TokenAuthenticator(tokens)
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := Listen(socket, ServerConfig{TLS: serverTLS, Authenticate: auth,
		Configure: func(context.Context, Principal, Request) (Route, error) {
			return NewDirectRoute(DirectPolicy{Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
		}, Application: func(_ context.Context, _ Principal, r Request) ([]byte, error) { return r.Payload, nil }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration+30*time.Second)
	defer cancel()
	go srv.Serve(ctx)
	defer srv.Shutdown(ctx)
	var sessions []*Session
	defer func() {
		for _, s := range sessions {
			s.Close()
		}
		for _, s := range sessions {
			if err := s.Wait(ctx); err != nil || s.localBudget.Load() != 0 {
				t.Errorf("session cleanup: %v, bytes=%d", err, s.localBudget.Load())
			}
		}
	}()
	for i := 0; i < 64; i++ {
		pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.%d:0", i/8+1))
		if err != nil {
			t.Fatal(err)
		}
		s, err := Dial(ctx, srv.Addr().String(), ClientConfig{TLS: clientTLS, Token: tokens[Principal(fmt.Sprint(i/4))], PacketConn: pc, Configuration: Request{Namespace: "direct", Version: 1}})
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		sessions = append(sessions, s)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.9:0")
	if err != nil {
		t.Fatal(err)
	}
	admission, stop := context.WithTimeout(ctx, time.Second)
	extra, err := Dial(admission, srv.Addr().String(), ClientConfig{TLS: clientTLS, Token: tokens["0"], PacketConn: pc, Configuration: Request{Namespace: "direct", Version: 1}})
	stop()
	if err == nil {
		extra.Close()
		t.Fatal("65th transport admitted")
	}
	l := tcpSink(t)
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, addr, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			udp.WriteTo(buffer[:n], addr)
		}
	}()
	until := time.Now().Add(duration)
	var wg sync.WaitGroup
	for index, s := range sessions {
		wg.Add(1)
		go func(index int, s *Session) {
			defer wg.Done()
			c, err := s.DialContext(ctx, l.Addr().String())
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			c.SetDeadline(until.Add(3 * time.Second))
			pc, err := s.ListenPacket(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			defer pc.Close()
			for iteration := 0; time.Now().Before(until); iteration++ {
				payload := []byte(fmt.Sprintf("%d/%d", index, iteration))
				reply, err := s.Message(ctx, Request{Namespace: "echo", Version: 1, Payload: payload})
				if err != nil || !bytes.Equal(reply, payload) {
					t.Errorf("control %d/%d: %v", index, iteration, err)
					return
				}
				_, err = c.Write(payload)
				buffer := make([]byte, len(payload))
				if _, readErr := io.ReadFull(c, buffer); err != nil || readErr != nil || !bytes.Equal(buffer, payload) {
					t.Errorf("TCP: %v, %v", err, readErr)
					return
				}
				pc.SetDeadline(time.Now().Add(time.Second))
				if _, err := pc.WriteTo(payload, udp.LocalAddr()); err != nil {
					t.Error(err)
					return
				}
				if n, addr, err := pc.ReadFrom(buffer); err == nil {
					if !bytes.Equal(buffer[:n], payload) || addr.String() != udp.LocalAddr().String() {
						t.Error("UDP payload or source mismatch")
						return
					}
				} else if e, ok := err.(net.Error); !ok || !e.Timeout() {
					t.Error(err)
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}(index, s)
	}
	wg.Wait()
	t.Logf("completed %s with %d authenticated sessions", duration, len(sessions))
}
