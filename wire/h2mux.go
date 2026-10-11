package wire

import (
	"bytes"
	"context"
	"errors"
	"io"
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

	mu   sync.Mutex
	cc   *http2.ClientConn
	conn net.Conn
	at   time.Time     // when cc was made
	n    *atomic.Int64 // bytes read and written on cc, for maxBytes
}

func newH2Mux(dial func(context.Context) (net.Conn, error), pingAfterIdle, pingTimeout time.Duration) *h2Mux {
	return &h2Mux{
		dial:       dial,
		tr:         &http2.Transport{ReadIdleTimeout: pingAfterIdle, PingTimeout: pingTimeout},
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
		return m.cc, m.conn, nil
	}
	old := m.cc
	c, err := m.dial(ctx)
	if err != nil {
		return nil, nil, err
	}
	n := new(atomic.Int64)
	c = &countConn{Conn: c, n: n}
	cc, err := m.tr.NewClientConn(c)
	if err != nil {
		c.Close()
		return nil, nil, err
	}
	if m.warm != nil {
		m.warm(ctx, cc)
	}
	if !cc.ReserveNewRequest() {
		cc.Close()
		c.Close()
		return nil, nil, errors.New("h2mux: a fresh connection would not take a stream")
	}
	m.cc, m.conn, m.at, m.n = cc, c, time.Now(), n
	if old != nil {
		m.retire(old)
	}
	return cc, c, nil
}

// expiredLocked reports whether the current connection has hit a rotation
// limit (maxAge, maxBytes) and should take no new streams. Held under m.mu.
func (m *h2Mux) expiredLocked() bool {
	if m.cc == nil {
		return false
	}
	if m.maxAge > 0 && time.Since(m.at) >= m.maxAge {
		return true
	}
	if m.maxBytes > 0 && m.n != nil && m.n.Load() >= m.maxBytes {
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
	return m.cc == nil || !m.cc.CanTakeNewRequest() || m.expiredLocked()
}

// retire lets a connection that takes no new streams finish the ones it
// carries, then closes it. A PING first tells a live connection from one that
// died in silence: a dead one is closed at once, so the flows stuck on it end
// instead of hanging until the system gives up on the socket (minutes), and a
// live one is never cut under the flows it carries.
func (m *h2Mux) retire(cc *http2.ClientConn) {
	ping := m.retirePing
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), ping)
		err := cc.Ping(ctx)
		cancel()
		if err != nil {
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
	old := m.cc
	if old == nil || !m.at.Before(t) {
		m.mu.Unlock()
		return
	}
	m.cc, m.conn = nil, nil
	m.mu.Unlock()
	m.retire(old)
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
			s.downErr = errors.New("h2mux: the server answered " + resp.Status)
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
type countConn struct {
	net.Conn
	n *atomic.Int64
}

func (c *countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.n.Add(int64(n))
	return n, err
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
	return s.up.Write(p)
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
