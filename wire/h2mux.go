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
	"time"

	"golang.org/x/net/http2"
)

// h2Mux carries many streams over one HTTP/2 connection and dials a fresh
// connection only when the current one is full or gone. It is the browser-like
// connection layer the private HTTPS transport ("kilvater", see
// KILVATER-SPEC.md) is built on: one TLS handshake holds up to the server's
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

	mu   sync.Mutex
	cc   *http2.ClientConn
	conn net.Conn
}

func newH2Mux(dial func(context.Context) (net.Conn, error), pingAfterIdle, pingTimeout time.Duration) *h2Mux {
	return &h2Mux{
		dial: dial,
		tr:   &http2.Transport{ReadIdleTimeout: pingAfterIdle, PingTimeout: pingTimeout},
	}
}

// client returns a connection that has just reserved a stream slot for the
// caller, dialing a new one if the current connection cannot take the stream.
// The caller must go on to RoundTrip, which consumes the reservation.
func (m *h2Mux) client(ctx context.Context) (*http2.ClientConn, net.Conn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cc != nil && m.cc.ReserveNewRequest() {
		return m.cc, m.conn, nil
	}
	old := m.cc
	c, err := m.dial(ctx)
	if err != nil {
		return nil, nil, err
	}
	cc, err := m.tr.NewClientConn(c)
	if err != nil {
		c.Close()
		return nil, nil, err
	}
	if !cc.ReserveNewRequest() {
		cc.Close()
		c.Close()
		return nil, nil, errors.New("h2mux: a fresh connection would not take a stream")
	}
	m.cc, m.conn = cc, c
	if old != nil {
		// The replaced connection keeps serving its open streams, then closes;
		// a stuck one is forced shut after a minute so it cannot leak.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if err := old.Shutdown(ctx); err != nil {
				old.Close()
			}
		}()
	}
	return cc, c, nil
}

// openStream starts one request/response stream on the shared connection. The
// returned net.Conn writes the request body (up) and reads the response body
// (down); its Close ends only this stream (RST_STREAM via the stream context),
// never the shared connection or the other streams on it.
func (m *h2Mux) openStream(ctx context.Context, method, reqURL string, header http.Header) (net.Conn, error) {
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
	req := (&http.Request{Method: method, URL: u, Host: u.Host, Header: header}).WithContext(sctx)
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
