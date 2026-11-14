package wire

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// h2Mux carries many streams over one HTTP/2 connection and dials a fresh
// connection only when the current one is full, gone, or past its rotation
// limits (maxAge, maxBytes). It is the browser-like
// connection layer the private HTTPS transport ("kilvater", see
// docs/KILVATER.md) is built on: one TLS handshake holds up to the server's
// stream limit of concurrent streams, so the handshake governor barely moves.
//
// The gRPC and XHTTP transports ride their streams on this layer too (one
// shared connection per path); kilvater adds its own stream kind on top.
//
// Freezes take care of themselves: the Transport's ReadIdleTimeout and
// PingTimeout make each ClientConn PING after an idle gap and drop itself if
// the pong never comes (golang.org/x/net/http2 readLoop → healthCheck). A
// dropped connection stops taking new requests, so the next openStream dials a
// new one. Pass 0/0 to leave the Transport's own defaults in place.
type h2Mux struct {
	dial func(context.Context) (net.Conn, error)
	tr   *http2.Transport

	// warm, when set, runs on each new connection before its first stream:
	// what a browser does on a connection before a script on the page makes
	// a request (kilvater fetches the page first).
	warm func(context.Context, *http2.ClientConn)

	// retirePing bounds the PING that tells a live retired connection from one
	// that died in silence (retire). Set once at construction.
	retirePing time.Duration

	// Rotation limits, 0 to disable (the default; kilvater sets them, the
	// other transports on this layer leave them off). A connection stops
	// taking new streams once it is older than maxAge or has carried more than
	// maxBytes; the next stream dials a fresh one and the old one drains
	// (retire), so no single connection is the whole tunnel, in time or in
	// volume. needsDial reports the coming dial, so the handshake governor
	// paces a rotation like any other handshake.
	maxAge   time.Duration
	maxBytes int64

	// spread makes each connection's own limits a random share of maxAge and
	// maxBytes, within ±spread of them (0: exactly the limits), so a client's
	// connections do not turn over on one clock.
	spread float64

	// ahead, when above 0, is the share of a connection's limit past which
	// the next connection is made in the background (dialed and warmed), so
	// the stream that rotates takes one that is ready instead of holding
	// every new stream behind a handshake and a page fetch. 0 turns it off:
	// the rotating stream dials, as before.
	ahead float64

	// onEnd, when set, hears of each connection's end: how it ended, the bytes
	// it had carried and when it was made (ConnWatcher). Set before the first
	// stream. lostPing is when the Transport last gave a connection up for a
	// PING left unanswered (unix nanoseconds).
	onEnd    func(end ConnEnd, bytes int64, made time.Time)
	lostPing atomic.Int64

	mu   sync.Mutex
	cc   *http2.ClientConn
	conn *countConn
	at   time.Time     // when cc was made
	n    *atomic.Int64 // bytes read and written on cc, for maxBytes

	ageLim  time.Duration // cc's own rotation limits (maxAge, maxBytes, spread)
	byteLim int64

	spare    *muxConn // the next connection, made ahead of the rotation
	sparing  bool     // one is being made
	spareGen int      // bumped to disown the one being made (refresh, Close)
}

// muxConn is a connection made and warmed, not yet the current one.
type muxConn struct {
	cc   *http2.ClientConn
	conn *countConn
	n    *atomic.Int64
	made time.Time
}

// spareDialTimeout bounds the making of the next connection in the background.
const spareDialTimeout = 30 * time.Second

// newConn dials and warms one connection. It takes no lock.
func (m *h2Mux) newConn(ctx context.Context) (*muxConn, error) {
	raw, err := m.dial(ctx)
	if err != nil {
		return nil, err
	}
	n := new(atomic.Int64)
	c := &countConn{Conn: raw, n: n, m: m, made: time.Now()}
	cc, err := m.tr.NewClientConn(&h2FrameCap{Conn: c})
	if err != nil {
		c.Close()
		return nil, err
	}
	if m.warm != nil {
		m.warm(ctx, cc)
	}
	return &muxConn{cc: cc, conn: c, n: n, made: c.made}, nil
}

// adoptLocked makes c the current connection and retires the one before it.
func (m *h2Mux) adoptLocked(c *muxConn) {
	old, oldConn := m.cc, m.conn
	m.cc, m.conn, m.at, m.n = c.cc, c.conn, time.Now(), c.n
	m.ageLim, m.byteLim = spreadDuration(m.maxAge, m.spread), int64(spreadDuration(time.Duration(m.maxBytes), m.spread))
	if old != nil {
		m.retire(old, oldConn)
	}
}

// spreadDuration is a random point within ±spread of d.
func spreadDuration(d time.Duration, spread float64) time.Duration {
	if d <= 0 || spread <= 0 {
		return d
	}
	return time.Duration(float64(d) * (1 - spread + 2*spread*rand.Float64()))
}

// dueLocked reports whether the current connection is far enough into a
// limit for the next one to be made ahead.
func (m *h2Mux) dueLocked() bool {
	if m.ahead <= 0 || m.cc == nil {
		return false
	}
	if m.ageLim > 0 && float64(time.Since(m.at)) >= m.ahead*float64(m.ageLim) {
		return true
	}
	return m.byteLim > 0 && m.n != nil && float64(m.n.Load()) >= m.ahead*float64(m.byteLim)
}

// spareAheadLocked starts the making of the next connection, once.
func (m *h2Mux) spareAheadLocked() {
	if m.sparing || m.spare != nil {
		return
	}
	m.sparing = true
	gen := m.spareGen
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), spareDialTimeout)
		c, err := m.newConn(ctx)
		cancel()
		m.mu.Lock()
		m.sparing = false
		if err == nil && gen == m.spareGen {
			m.spare = c
			c = nil
		}
		m.mu.Unlock()
		if c != nil {
			c.cc.Close()
			c.conn.Close()
		}
	}()
}

// takeSpareLocked hands over the connection made ahead if it can still carry
// a stream, reserving one on it; a spare that died waiting is dropped.
func (m *h2Mux) takeSpareLocked() *muxConn {
	c := m.spare
	if c == nil {
		return nil
	}
	m.spare = nil
	if (m.maxAge > 0 && time.Since(c.made) >= m.maxAge) || !c.cc.ReserveNewRequest() {
		c.cc.Close()
		c.conn.Close()
		return nil
	}
	return c
}

// dropSpareLocked gives up the connection made ahead, and the one being made.
func (m *h2Mux) dropSpareLocked() {
	m.spareGen++
	if c := m.spare; c != nil {
		m.spare = nil
		c.cc.Close()
		c.conn.Close()
	}
}

// h2StreamWindow is how much one stream may hold that the app has not read
// yet: the SETTINGS_INITIAL_WINDOW_SIZE this layer's own Transport advertises.
// Go's default is 4 MiB per stream, and on a phone that is the memory: when an
// app stops reading (a player with enough buffered, a stalled download) the
// server fills the whole window and it sits in the tunnel's heap, stream after
// stream, while the iOS packet tunnel is killed near 50 MB. 2 MiB halves that
// and costs no speed from Russia: 25 MB through gRPC and XHTTP paths from
// Novosibirsk (67 ms to the nodes, ~60 Mbit/s) took as long as with 4 MiB,
// while 1 MiB was up to 30% slower there and ~40% slower over a longer path.
// A transport that wears a browser's HTTP/2 (h2Profile.transport) replaces tr
// and advertises that browser's own window instead.
const h2StreamWindow = 2 << 20

// h2ConnWindow caps what all the streams of one connection may hold unread
// together. Go's default is 1 GiB, and stalled streams added up: on iOS 1.0.1
// (38) the packet tunnel died of jetsam's per-process limit in 47% of the
// sessions it ended under an XHTTP leader, against 8% under Reality, whose
// unread bytes wait in the kernel instead. Three stalled streams' worth, about
// Chrome's 2.5: a stream that keeps reading never waits on one stalled stream,
// and on three only until one of them reads again.
const h2ConnWindow = 3 * h2StreamWindow

func newH2Mux(dial func(context.Context) (net.Conn, error), pingAfterIdle, pingTimeout time.Duration) *h2Mux {
	t2, err := http2.ConfigureTransports(&http.Transport{HTTP2: &http.HTTP2Config{
		MaxReceiveBufferPerStream:     h2StreamWindow,
		MaxReceiveBufferPerConnection: h2ConnWindow,
	}})
	if err != nil {
		// Only fails when the http.Transport already has h2 set up, which a fresh one never has.
		panic(err)
	}
	t2.ReadIdleTimeout, t2.PingTimeout = pingAfterIdle, pingTimeout
	return &h2Mux{
		dial:       dial,
		tr:         t2,
		retirePing: defaultRetirePing,
	}
}

// client returns a connection that has just reserved a stream slot for the
// caller, dialing a new one if the current connection cannot take the stream.
// The caller must go on to RoundTrip, which consumes the reservation.
func (m *h2Mux) client(ctx context.Context) (*http2.ClientConn, net.Conn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cc != nil && !m.expiredLocked() && m.cc.ReserveNewRequest() {
		if m.dueLocked() {
			m.spareAheadLocked()
		}
		return m.cc, m.conn, nil
	}
	if c := m.takeSpareLocked(); c != nil {
		m.adoptLocked(c)
		return c.cc, c.conn, nil
	}
	if m.onEnd != nil && m.tr.CountError == nil {
		// The Transport names the error just before it closes the connection
		// (closeForLostPing), on the same goroutine: countConn.Close reads it.
		m.tr.CountError = func(kind string) {
			if kind == "conn_close_lost_ping" {
				m.lostPing.Store(time.Now().UnixNano())
			}
		}
	}
	c, err := m.newConn(ctx)
	if err != nil {
		return nil, nil, err
	}
	if !c.cc.ReserveNewRequest() {
		c.cc.Close()
		c.conn.Close()
		return nil, nil, errors.New("h2mux: a fresh connection would not take a stream")
	}
	m.adoptLocked(c)
	return c.cc, c.conn, nil
}

// expiredLocked reports whether the current connection has hit a rotation
// limit (maxAge, maxBytes) and should take no new streams. Held under m.mu.
func (m *h2Mux) expiredLocked() bool {
	if m.cc == nil {
		return false
	}
	if m.ageLim > 0 && time.Since(m.at) >= m.ageLim {
		return true
	}
	if m.byteLim > 0 && m.n != nil && m.n.Load() >= m.byteLim {
		return true
	}
	return false
}

// needsDial reports whether the next stream would dial a connection, and so
// run a TLS handshake: there is none yet, the current one takes no more
// streams (closed, closing or full), or it is past a rotation limit, so the
// next stream rotates to a fresh one. The handshake governor paces by this,
// so a rotation's handshake is paced like any other.
func (m *h2Mux) needsDial() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cc != nil && m.cc.CanTakeNewRequest() && !m.expiredLocked() {
		return false
	}
	// A connection made ahead takes the stream with no handshake.
	return m.spare == nil || !m.spare.cc.CanTakeNewRequest()
}

// retire lets a connection that takes no new streams finish the ones it
// carries, then closes it. A PING first tells a live connection from one that
// died in silence: a dead one is closed at once, so the flows stuck on it end
// instead of hanging until the system gives up on the socket (minutes), and a
// live one is never cut under the flows it carries.
func (m *h2Mux) retire(cc *http2.ClientConn, conn *countConn) {
	ping := m.retirePing
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), ping)
		err := cc.Ping(ctx)
		cancel()
		if err != nil {
			if conn != nil {
				conn.ended(ConnEndDead)
			}
			cc.Close()
			return
		}
		_ = cc.Shutdown(context.Background())
	}()
}

// defaultRetirePing: a retired connection that does not answer a PING this
// long is taken for dead.
const defaultRetirePing = 10 * time.Second

// refresh stops new streams from riding the current connection if it was made
// before t, as it may have died in silence since (a NAT that forgot it, a
// network the phone left): the next stream dials a fresh one. Streams already
// on it finish there (retire). One made since is left alone: several flows
// that met the dead connection at once retire it once, not each new one.
func (m *h2Mux) refresh(t time.Time) {
	m.mu.Lock()
	old, oldConn := m.cc, m.conn
	if m.sparing || (m.spare != nil && m.spare.made.Before(t)) {
		// One being made started on the network as it was: disown it too.
		m.dropSpareLocked()
	}
	if old == nil || !m.at.Before(t) {
		m.mu.Unlock()
		return
	}
	m.cc, m.conn = nil, nil
	m.mu.Unlock()
	m.retire(old, oldConn)
}

// openStream starts one request/response stream on the shared connection. The
// returned net.Conn writes the request body (up) and reads the response body
// (down); its Close ends only this stream (RST_STREAM via the stream context),
// never the shared connection or the other streams on it.
func (m *h2Mux) openStream(ctx context.Context, method, reqURL string, header http.Header) (net.Conn, error) {
	return m.openStreamFunc(ctx, method, reqURL, func() http.Header { return header })
}

// openStreamFunc is openStream with the header made once the connection is
// ready, after a new one has been warmed (kilvater's tag takes the server's
// clock from that).
func (m *h2Mux) openStreamFunc(ctx context.Context, method, reqURL string, header func() http.Header) (net.Conn, error) {
	u, err := url.Parse(reqURL)
	if err != nil {
		return nil, err
	}
	cc, conn, err := m.client(ctx)
	if err != nil {
		return nil, err
	}
	// The stream outlives the dial context (the switchboard cancels the dial as
	// soon as Dial returns, but a flow runs for minutes); its own cancel, fired
	// by Close, governs its life from here.
	sctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	up := pw
	var body io.ReadCloser = pr
	if method == http.MethodGet {
		pr.Close()
		body, up = nil, nil
	}
	req := (&http.Request{Method: method, URL: u, Host: u.Host, Header: header()}).WithContext(sctx)
	if body != nil {
		req.Body = body
	}
	s := &h2MuxStream{up: up, conn: conn, cancel: cancel, ready: make(chan struct{})}
	go func() {
		resp, err := cc.RoundTrip(req)
		if err != nil {
			s.downErr = err
			close(s.ready)
			pw.CloseWithError(err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			s.downErr = &H2StatusError{Code: resp.StatusCode, Status: resp.Status}
			resp.Body.Close()
			close(s.ready)
			pw.CloseWithError(s.downErr)
			return
		}
		s.down = resp.Body
		close(s.ready)
	}()
	return s, nil
}

// post sends one complete request over the shared connection and discards the
// response — the per-chunk upload packet-up XHTTP uses. The body is whole, so
// it rides one stream on the shared connection and opens no new handshake.
func (m *h2Mux) post(ctx context.Context, reqURL string, header http.Header, body []byte) error {
	u, err := url.Parse(reqURL)
	if err != nil {
		return err
	}
	cc, _, err := m.client(ctx)
	if err != nil {
		return err
	}
	req := (&http.Request{Method: http.MethodPost, URL: u, Host: u.Host, Header: header,
		Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}).WithContext(ctx)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("h2mux: upload answered " + resp.Status)
	}
	return nil
}

// Close tears the mux down: the current connection and its streams go away.
func (m *h2Mux) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dropSpareLocked()
	if m.cc != nil {
		m.cc.Close()
		m.cc = nil
	}
	if m.conn != nil {
		err := m.conn.Close()
		m.conn = nil
		return err
	}
	return nil
}

// countConn sums the bytes read and written on a connection, for the mux's
// volume-based rotation (maxBytes). The mux reads the count under m.mu while
// the stream goroutines write it here off the lock, so it is atomic.
//
// It also tells the mux how the connection ended (h2Mux.onEnd), once, by what
// came first: a read that failed (the far side closed it, or it broke), or a
// Close of ours (the Transport giving it up for an unanswered PING, or the mux
// letting it go).
type countConn struct {
	net.Conn
	n    *atomic.Int64
	m    *h2Mux
	made time.Time
	once sync.Once
}

func (c *countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.n.Add(int64(n))
	if err != nil {
		if errors.Is(err, io.EOF) {
			c.ended(ConnEndFin)
		} else if !errors.Is(err, net.ErrClosed) {
			c.ended(ConnEndReset)
		}
	}
	return n, err
}

// lostPingSlack is how long after the Transport named a lost PING a Close is
// still taken for that connection's: the two follow each other on one goroutine.
const lostPingSlack = 200 * time.Millisecond

func (c *countConn) Close() error {
	end := ConnEndOurs
	if c.m != nil && time.Since(time.Unix(0, c.m.lostPing.Load())) < lostPingSlack {
		end = ConnEndDead
	}
	c.ended(end)
	return c.Conn.Close()
}

// ended reports the connection's end to the mux's watcher, the first time only.
func (c *countConn) ended(end ConnEnd) {
	if c.m == nil || c.m.onEnd == nil {
		return
	}
	c.once.Do(func() { c.m.onEnd(end, c.n.Load(), c.made) })
}

func (c *countConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.n.Add(int64(n))
	return n, err
}

// h2MuxStream is one stream on a shared h2Mux connection, presented as a
// net.Conn. It does not own the connection: Close ends the stream alone,
// leaving the shared connection and its other streams running.
type h2MuxStream struct {
	up     *io.PipeWriter
	down   io.ReadCloser
	conn   net.Conn // the shared connection, for addresses only; never closed here
	cancel context.CancelFunc

	downErr error
	ready   chan struct{}
}

func (s *h2MuxStream) Read(p []byte) (int, error) {
	<-s.ready
	if s.downErr != nil {
		return 0, s.downErr
	}
	return s.down.Read(p)
}

func (s *h2MuxStream) Write(p []byte) (int, error) {
	if s.up == nil {
		return 0, io.ErrClosedPipe
	}
	n, err := s.up.Write(p)
	if err != nil {
		// The transport closes the request body once the stream is over, so
		// a write that loses that race sees only a closed pipe. The answer
		// that ended the stream is the error worth returning (a refusal must
		// not pass for a broken path); it is known as soon as RoundTrip is.
		<-s.ready
		if s.downErr != nil {
			return n, s.downErr
		}
	}
	return n, err
}

// CloseWrite ends the request body, leaving the response to be read.
func (s *h2MuxStream) CloseWrite() error {
	if s.up == nil {
		return nil
	}
	return s.up.Close()
}

func (s *h2MuxStream) Close() error {
	if s.up != nil {
		s.up.Close()
	}
	s.cancel()
	// cancel makes the in-flight RoundTrip return, so ready closes shortly;
	// waiting for it is what lets us read s.down without racing the goroutine
	// that sets it.
	<-s.ready
	if s.down != nil {
		s.down.Close()
	}
	return nil
}

func (s *h2MuxStream) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *h2MuxStream) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }
func (s *h2MuxStream) SetDeadline(t time.Time) error      { return nil }
func (s *h2MuxStream) SetReadDeadline(t time.Time) error  { return nil }
func (s *h2MuxStream) SetWriteDeadline(t time.Time) error { return nil }

var _ net.Conn = (*h2MuxStream)(nil)

// H2StatusError is a stream the server answered with something other than
// 200: the connection, TLS and HTTP/2 all worked, and the server chose not to
// serve the request. A transport that knows what that means of its server
// (kilvater: the key was not accepted) reads the code with errors.As.
type H2StatusError struct {
	Code   int
	Status string
}

func (e *H2StatusError) Error() string { return "h2mux: the server answered " + e.Status }
