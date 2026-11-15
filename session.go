package quri

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	quic "github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

// Principal is the authenticated identity supplied to host callbacks.
type Principal string

// Route is an authorized, session-local outbound. Implementations must support
// concurrent calls, enforce destination policy and honor cancellation.
type Route interface {
	DialContext(context.Context, string) (net.Conn, error)
	ListenPacket(context.Context) (net.PacketConn, error)
	Close() error
}

// ClientConfig configures a single immutable session. TLS must verify the server.
// PacketConn, when supplied, is transferred to the session and closed with it.
type ClientConfig struct {
	TLS           *tls.Config
	Token         string
	Configuration Request
	PacketConn    net.PacketConn
	// Application handles server-initiated messages from the verified peer.
	Application func(context.Context, Request) ([]byte, error)
}

type frame struct {
	kind byte
	id   uint64
	data []byte
}

const (
	configureKind   byte = 1
	applicationKind byte = 2
	drainKind       byte = 3
	responseKind    byte = 0x80
)

func readFrame(r io.Reader, reserve func(int64) bool) (frame, error) {
	var h [13]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return frame{}, err
	}
	n := binary.BigEndian.Uint32(h[9:])
	if n > maxControl {
		return frame{}, ErrLimit
	}
	if !reserve(int64(n)) {
		return frame{}, ErrLimit
	}
	b := make([]byte, int(n))
	_, err := io.ReadFull(r, b)
	return frame{kind: h[0], id: binary.BigEndian.Uint64(h[1:9]), data: b}, err
}

// Session owns the transport and all of its streams and associations. Close
// aborts immediately; Shutdown cooperatively drains both peers until ctx expires.
type Session struct {
	conn           *quic.Conn
	control        *quic.Stream
	transport      *quic.Transport
	socket         net.PacketConn
	principal      Principal
	application    func(context.Context, Request) ([]byte, error)
	server         *Server
	route          Route
	handle         uint64
	mu             sync.Mutex
	streams        map[*Stream]struct{}
	packets        map[uint64]*PacketConn
	opening        int
	draining       bool
	changed        chan struct{}
	writeGate      chan struct{}
	requestGate    chan struct{}
	nextID         uint64
	pending        chan frame
	pendingID      uint64
	pendingKind    byte
	localBudget    atomic.Int64
	globalBudget   *bufferBudget
	dataBudget     atomic.Int64
	assembly       reassembler
	stats          counters
	wg             sync.WaitGroup
	closeOnce      sync.Once
	finished       chan struct{}
	udpIdleTimeout time.Duration
}

func quicConfig() *quic.Config {
	return &quic.Config{
		Versions: []quic.Version{quic.Version1}, EnableDatagrams: true, Allow0RTT: false,
		MaxIncomingStreams: maxStreams + maxAssociations + 1, MaxIncomingUniStreams: -1,
		InitialStreamReceiveWindow: 64 << 10, MaxStreamReceiveWindow: 64 << 10,
		InitialConnectionReceiveWindow: 8 << 20, MaxConnectionReceiveWindow: 8 << 20,
		HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 45 * time.Second, KeepAlivePeriod: 15 * time.Second,
		InitialPacketSize: 1200,
	}
}

type bufferBudget struct {
	total atomic.Int64
	data  atomic.Int64
}

func newSession(c *quic.Conn, control *quic.Stream, global *bufferBudget) *Session {
	s := &Session{conn: c, control: control, streams: make(map[*Stream]struct{}), packets: make(map[uint64]*PacketConn), changed: make(chan struct{}), requestGate: make(chan struct{}, 1), writeGate: make(chan struct{}, 1), globalBudget: global, finished: make(chan struct{}), udpIdleTimeout: 60 * time.Second}
	s.requestGate <- struct{}{}
	s.writeGate <- struct{}{}
	s.assembly.entries = make(map[messageKey]*assembly)
	return s
}

// Dial authenticates, negotiates quri/1 and accepts Configuration before returning.
func Dial(ctx context.Context, address string, cfg ClientConfig) (*Session, error) {
	if cfg.TLS == nil || cfg.TLS.InsecureSkipVerify || len(cfg.Token) < 32 || len(cfg.Token) > 256 {
		return nil, ErrDenied
	}
	tc := cfg.TLS.Clone()
	tc.NextProtos = []string{alpn}
	tc.MinVersion = tls.VersionTLS13
	tc.ClientSessionCache = nil
	pc := cfg.PacketConn
	if pc == nil {
		var err error
		pc, err = net.ListenUDP("udp", nil)
		if err != nil {
			return nil, err
		}
	}
	tr := &quic.Transport{Conn: pc}
	fail := func() { tr.Close(); pc.Close() }
	host, service, err := net.SplitHostPort(address)
	if err != nil {
		fail()
		return nil, err
	}
	port, err := strconv.Atoi(service)
	if err != nil || port < 1 || port > 65535 {
		fail()
		return nil, ErrProtocol
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		fail()
		return nil, err
	}
	if len(ips) == 0 {
		fail()
		return nil, ErrDenied
	}
	ip := ips[0]
	for _, candidate := range ips {
		if candidate.Is4() {
			ip = candidate
			break
		}
	}
	addr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(port)))
	if tc.ServerName == "" {
		tc.ServerName, _, err = net.SplitHostPort(address)
		if err != nil {
			fail()
			return nil, err
		}
	}
	qc := quicConfig()
	qc.MaxIncomingStreams = -1
	c, err := tr.Dial(ctx, addr, tc, qc)
	if err != nil {
		fail()
		return nil, err
	}
	failConn := func() { c.CloseWithError(1, "handshake failed"); fail() }
	control, err := c.OpenStreamSync(ctx)
	if err != nil {
		failConn()
		return nil, err
	}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	control.SetDeadline(deadline)
	stopWatch := watchCancellation(ctx, control.SetDeadline)
	defer stopWatch()
	if err = writeJSON(control, hello{Version: 1, Token: cfg.Token, UDP: true}, maxOpen); err != nil {
		failConn()
		return nil, err
	}
	var accepted response
	if err = readJSON(control, &accepted, maxOpen); err != nil {
		failConn()
		return nil, err
	}
	if accepted.Error != "" {
		failConn()
		return nil, ErrDenied
	}
	if !c.ConnectionState().SupportsDatagrams.Remote {
		failConn()
		return nil, ErrProtocol
	}
	stopWatch()
	control.SetDeadline(time.Time{})
	global := new(bufferBudget)
	s := newSession(c, control, global)
	s.transport = tr
	s.socket = pc
	s.application = cfg.Application
	s.start()
	data, err := s.request(ctx, configureKind, cfg.Configuration)
	if err != nil {
		s.Close()
		return nil, err
	}
	s.handle = data.Handle
	if s.handle == 0 {
		s.Close()
		return nil, ErrProtocol
	}
	return s, nil
}

func (s *Session) start() {
	s.wg.Add(2)
	go func() { defer s.wg.Done(); s.readControl() }()
	go func() { defer s.wg.Done(); s.readDatagrams() }()
	if s.server != nil {
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.acceptStreams() }()
	}
	go func() {
		<-s.conn.Context().Done()
		s.Close()
		s.wg.Wait()
		s.assembly.clear(s)
		if s.route != nil {
			s.route.Close()
		}
		close(s.finished)
	}()
}

func (s *Session) notifyLocked() { close(s.changed); s.changed = make(chan struct{}) }
func (s *Session) removeStream(st *Stream) {
	s.mu.Lock()
	delete(s.streams, st)
	s.notifyLocked()
	s.mu.Unlock()
}
func (s *Session) reserveOpen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.draining {
		return ErrDraining
	}
	if s.opening >= maxStreams+maxAssociations || len(s.streams)+len(s.packets) >= maxStreams+maxAssociations {
		return ErrLimit
	}
	s.opening++
	return nil
}
func (s *Session) releaseOpen() { s.mu.Lock(); s.opening--; s.notifyLocked(); s.mu.Unlock() }

func (s *Session) sendFrame(ctx context.Context, f frame) error {
	if len(f.data) > maxControl {
		return ErrLimit
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.conn.Context().Done():
		return net.ErrClosed
	case <-s.writeGate:
	}
	defer func() { s.writeGate <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	s.control.SetWriteDeadline(deadline)
	stopWatch := watchCancellation(ctx, s.control.SetWriteDeadline)
	defer stopWatch()
	var h [13]byte
	h[0] = f.kind
	binary.BigEndian.PutUint64(h[1:9], f.id)
	binary.BigEndian.PutUint32(h[9:13], uint32(len(f.data)))
	err := writeAll(s.control, h[:])
	if err == nil {
		err = writeAll(s.control, f.data)
	}
	if err != nil {
		s.conn.CloseWithError(1, "control write failed")
	}
	return err
}

func (s *Session) request(ctx context.Context, kind byte, req Request) (response, error) {
	timeout := 5 * time.Second
	if kind == drainKind {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if len(req.Payload) > maxApplication {
		return response{}, ErrLimit
	}
	if kind != drainKind && (req.Namespace == "" || len(req.Namespace) > 128 || !utf8.ValidString(req.Namespace) || req.Version == 0) {
		return response{}, ErrProtocol
	}
	select {
	case <-ctx.Done():
		return response{}, ctx.Err()
	case <-s.conn.Context().Done():
		return response{}, net.ErrClosed
	case <-s.requestGate:
	}
	defer func() { s.requestGate <- struct{}{} }()
	if !s.reserveBytes(maxControl) {
		return response{}, ErrLimit
	}
	defer s.releaseBytes(maxControl)
	b, err := json.Marshal(req)
	if err != nil {
		return response{}, err
	}
	if len(b) > maxControl {
		return response{}, ErrLimit
	}
	s.mu.Lock()
	s.nextID++
	id := s.nextID
	ch := make(chan frame, 1)
	s.pendingID = id
	s.pendingKind = kind | responseKind
	s.pending = ch
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.pending = nil; s.mu.Unlock() }()
	if err = s.sendFrame(ctx, frame{kind: kind, id: id, data: b}); err != nil {
		return response{}, err
	}
	select {
	case <-ctx.Done():
		return response{}, ctx.Err()
	case <-s.conn.Context().Done():
		return response{}, net.ErrClosed
	case f := <-ch:
		var r response
		if json.Unmarshal(f.data, &r) != nil {
			return response{}, ErrProtocol
		}
		if r.Error != "" {
			return response{}, &RemoteError{Code: r.Code, Message: r.Error}
		}
		return r, nil
	}
}

// Message exchanges one typed application request. Hosts define its schema and
// side effects; canceled requests are never automatically retried.
func (s *Session) Message(ctx context.Context, req Request) ([]byte, error) {
	r, err := s.request(ctx, applicationKind, req)
	return r.Payload, err
}

type cachedReply struct {
	hash [32]byte
	data []byte
	kind byte
}

func (s *Session) readControl() {
	cache := make(map[uint64]cachedReply)
	var highWater uint64
	cachedBytes := int64(0)
	held := int64(0)
	defer func() { s.releaseBytes(cachedBytes + held) }()
	for {
		s.releaseBytes(held)
		held = 0
		var first [1]byte
		_, err := io.ReadFull(s.control, first[:])
		if err != nil {
			s.conn.CloseWithError(1, "control read failed")
			return
		}
		s.control.SetReadDeadline(time.Now().Add(5 * time.Second))
		f, err := readFrame(io.MultiReader(bytes.NewReader(first[:]), s.control), s.reserveBytes)
		s.control.SetReadDeadline(time.Time{})
		held = int64(len(f.data))
		if err != nil {
			s.conn.CloseWithError(1, "control read failed")
			return
		}
		if f.id == 0 || !utf8.Valid(f.data) {
			s.Close()
			return
		}
		if f.kind&responseKind != 0 {
			s.mu.Lock()
			if s.pending != nil && s.pendingID == f.id {
				if f.kind != s.pendingKind {
					s.mu.Unlock()
					s.Close()
					return
				}
				select {
				case s.pending <- f:
				default:
				}
			}
			s.mu.Unlock()
			continue
		}
		hash := sha256.Sum256(f.data)
		var reply []byte
		if previous, ok := cache[f.id]; ok {
			if previous.hash != hash || previous.kind != f.kind {
				s.Close()
				return
			}
			reply = previous.data
		} else {
			if f.id <= highWater {
				reply, _ := json.Marshal(response{Error: "request result expired; operation not reapplied"})
				if s.sendFrame(s.conn.Context(), frame{kind: f.kind | responseKind, id: f.id, data: reply}) != nil {
					return
				}
				continue
			}
			highWater = f.id

			var req Request
			var result response
			if json.Unmarshal(f.data, &req) != nil {
				result.Error = "invalid request"
			} else {
				timeout := 5 * time.Second
				if f.kind == drainKind {
					timeout = 10 * time.Second
				}
				ctx, cancel := context.WithTimeout(s.conn.Context(), timeout)
				result = s.handleRequest(ctx, f.kind, req)
				cancel()
			}
			reply, err = json.Marshal(result)
			if err != nil || len(reply) > maxControl {
				s.Close()
				return
			}
			for len(cache) >= maxCachedReplies || cachedBytes+int64(len(reply)) > 2<<20 {
				var oldest uint64
				for id := range cache {
					if oldest == 0 || id < oldest {
						oldest = id
					}
				}
				if oldest == 0 {
					break
				}
				size := int64(len(cache[oldest].data))
				delete(cache, oldest)
				cachedBytes -= size
				s.releaseBytes(size)
			}
			if !s.reserveBytes(int64(len(reply))) {
				s.Close()
				return
			}
			cachedBytes += int64(len(reply))
			cache[f.id] = cachedReply{hash: hash, data: reply, kind: f.kind}
		}
		if err = s.sendFrame(s.conn.Context(), frame{kind: f.kind | responseKind, id: f.id, data: reply}); err != nil {
			return
		}
	}
}

func (s *Session) handleRequest(ctx context.Context, kind byte, req Request) response {
	if kind == drainKind {
		if err := s.drain(ctx); err != nil {
			return response{Error: "drain timeout"}
		}
		return response{}
	}
	if req.Namespace == "" || len(req.Namespace) > 128 || req.Version == 0 || len(req.Payload) > maxApplication {
		return response{Error: "invalid application schema"}
	}
	switch kind {
	case configureKind:
		if s.server == nil {
			return response{Error: "request not supported"}
		}
		s.mu.Lock()
		exists := s.route != nil || s.draining
		s.mu.Unlock()
		if exists {
			return response{Error: "configuration immutable"}
		}
		route, err := s.server.cfg.Configure(ctx, s.principal, req)
		if err != nil || route == nil {
			if route != nil {
				route.Close()
			}
			return response{Error: "configuration denied"}
		}
		s.mu.Lock()
		if ctx.Err() != nil || s.draining || s.conn.Context().Err() != nil {
			s.mu.Unlock()
			route.Close()
			return response{Error: "session unavailable"}
		}
		s.route = route
		s.handle = 1
		s.mu.Unlock()
		return response{Handle: 1}
	case applicationKind:
		if s.application == nil {
			return response{Error: "application not supported"}
		}
		b, err := s.application(ctx, req)
		if err != nil {
			return response{Error: "application rejected"}
		}
		if len(b) > maxApplication {
			return response{Error: "response too large"}
		}
		return response{Payload: b}
	default:
		if kind&0x40 != 0 {
			return response{}
		}
		return response{Error: "unsupported mandatory request"}
	}
}

func (s *Session) open(ctx context.Context, kind, address string) (*quic.Stream, error) {
	if kind == "tcp" {
		if err := validAddress(address); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
	}
	st, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			st.CancelRead(1)
			st.CancelWrite(1)
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	if d, yes := ctx.Deadline(); yes && d.Before(deadline) {
		deadline = d
	}
	st.SetDeadline(deadline)
	stopWatch := watchCancellation(ctx, st.SetDeadline)
	defer stopWatch()
	if err = writeJSON(st, open{Kind: kind, Handle: s.handle, Address: address}, maxOpen); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	var r response
	if err = readJSON(st, &r, maxOpen); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if r.Error != "" {
		return nil, &RemoteError{Code: r.Code, Message: r.Error}
	}
	stopWatch()
	st.SetDeadline(time.Time{})
	ok = true
	return st, nil
}

// DialContext opens a TCP flow after the remote host accepts the destination.
func (s *Session) DialContext(ctx context.Context, address string) (*Stream, error) {
	if err := s.reserveOpen(); err != nil {
		return nil, err
	}
	defer s.releaseOpen()
	s.mu.Lock()
	full := len(s.streams) >= maxStreams
	s.mu.Unlock()
	if full {
		return nil, ErrLimit
	}
	st, err := s.open(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	stream := &Stream{stream: st, session: s}
	s.mu.Lock()
	if s.draining || len(s.streams) >= maxStreams {
		s.mu.Unlock()
		st.CancelRead(1)
		st.CancelWrite(1)
		return nil, ErrLimit
	}
	s.streams[stream] = struct{}{}
	s.mu.Unlock()
	return stream, nil
}

func (s *Session) acceptStreams() {
	for {
		st, err := s.conn.AcceptStream(s.conn.Context())
		if err != nil {
			return
		}
		if err = s.reserveOpen(); err != nil {
			st.CancelRead(2)
			st.CancelWrite(2)
			continue
		}
		s.wg.Add(1)
		go func() { defer s.wg.Done(); defer s.releaseOpen(); s.serveStream(st) }()
	}
}

func (s *Session) serveStream(st *quic.Stream) {
	ok := false
	defer func() {
		if !ok {
			st.CancelRead(1)
			st.CancelWrite(1)
		}
	}()
	st.SetDeadline(time.Now().Add(5 * time.Second))
	var req open
	if readJSON(st, &req, maxOpen) != nil {
		return
	}
	s.mu.Lock()
	route := s.route
	idleTimeout := s.udpIdleTimeout
	valid := route != nil && req.Handle == s.handle && !s.draining
	s.mu.Unlock()
	reject := func(err error) { writeJSON(st, failure(err), maxOpen); st.Close(); st.CancelRead(1) }
	if !valid {
		reject(ErrDenied)
		ok = true
		return
	}
	ctx, cancel := context.WithTimeout(s.conn.Context(), 5*time.Second)
	defer cancel()
	switch req.Kind {
	case "tcp":
		if validAddress(req.Address) != nil {
			reject(ErrProtocol)
			ok = true
			return
		}
		s.mu.Lock()
		full := len(s.streams) >= maxStreams
		s.mu.Unlock()
		if full {
			reject(ErrLimit)
			ok = true
			return
		}
		target, err := route.DialContext(ctx, req.Address)
		if err != nil {
			reject(err)
			ok = true
			return
		}
		defer target.Close()
		stream := &Stream{stream: st, session: s}
		s.mu.Lock()
		if s.draining || len(s.streams) >= maxStreams {
			s.mu.Unlock()
			reject(ErrLimit)
			ok = true
			return
		}
		s.streams[stream] = struct{}{}
		s.mu.Unlock()
		defer stream.Close()
		if err = writeJSON(st, response{}, maxOpen); err != nil {
			return
		}
		st.SetDeadline(time.Time{})
		ok = true
		Relay(stream, target)
	case "udp":
		pc, err := route.ListenPacket(ctx)
		if err != nil {
			reject(err)
			ok = true
			return
		}
		packet, err := s.addPacket(st)
		if err != nil {
			pc.Close()
			reject(err)
			ok = true
			return
		}
		defer packet.Close()
		defer pc.Close()
		if err = writeJSON(st, response{}, maxOpen); err != nil {
			return
		}
		st.SetDeadline(time.Time{})
		ok = true
		s.relayPackets(packet, pc, idleTimeout)
	default:
		reject(ErrProtocol)
		ok = true
	}
}

func (s *Session) drain(ctx context.Context) error {
	s.mu.Lock()
	s.draining = true
	for len(s.streams)+len(s.packets)+s.opening > 0 {
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.conn.Context().Done():
			return net.ErrClosed
		case <-changed:
		}
		s.mu.Lock()
	}
	s.mu.Unlock()
	return nil
}

// Shutdown stops new work and waits for both peers to finish active flows.
func (s *Session) Shutdown(ctx context.Context) error {
	if err := s.drain(ctx); err != nil {
		s.Close()
		return err
	}
	_, err := s.request(ctx, drainKind, Request{})
	s.Close()
	return err
}

// Close aborts all flows and releases the owned transport. Wait observes cleanup.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		s.conn.CloseWithError(0, "closed")
		s.mu.Lock()
		s.draining = true
		streams := make([]*Stream, 0, len(s.streams))
		for st := range s.streams {
			streams = append(streams, st)
		}
		packets := make([]*PacketConn, 0, len(s.packets))
		for _, p := range s.packets {
			packets = append(packets, p)
		}
		s.notifyLocked()
		s.mu.Unlock()
		for _, st := range streams {
			st.Close()
		}
		for _, p := range packets {
			p.Close()
		}
		if s.transport != nil {
			s.transport.Close()
		}
		if s.socket != nil {
			s.socket.Close()
		}
	})
	return nil
}

// Wait waits for transport readers and host handlers to release session resources.
func (s *Session) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.finished:
		return nil
	}
}

func (s *Session) reserveBytes(n int64) bool {
	if s.localBudget.Add(n) > 16<<20 {
		s.localBudget.Add(-n)
		return false
	}
	if s.globalBudget.total.Add(n) > 128<<20 {
		s.globalBudget.total.Add(-n)
		s.localBudget.Add(-n)
		return false
	}
	return true
}
func (s *Session) releaseBytes(n int64) { s.localBudget.Add(-n); s.globalBudget.total.Add(-n) }

var _ net.Conn = (*Stream)(nil)

// watchCancellation interrupts a bounded stream operation without requiring Go
// 1.21 context.AfterFunc. Stop waits before a caller clears the deadline.
func watchCancellation(ctx context.Context, set func(time.Time) error) func() {
	done := make(chan struct{})
	stopped := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			set(time.Now())
		case <-done:
		}
	}()
	return func() { once.Do(func() { close(done) }); <-stopped }
}

func (s *Session) reserveDatagramBytes(n int64) bool {
	if s.dataBudget.Add(n) > 8<<20 {
		s.dataBudget.Add(-n)
		return false
	}
	// Leave process-wide headroom for control when UDP queues are saturated.
	if s.globalBudget.data.Add(n) > 96<<20 {
		s.globalBudget.data.Add(-n)
		s.dataBudget.Add(-n)
		return false
	}
	if !s.reserveBytes(n) {
		s.globalBudget.data.Add(-n)
		s.dataBudget.Add(-n)
		return false
	}
	return true
}
func (s *Session) releaseDatagramBytes(n int64) {
	s.dataBudget.Add(-n)
	s.globalBudget.data.Add(-n)
	s.releaseBytes(n)
}
