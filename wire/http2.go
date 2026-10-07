package wire

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/http2"
)

// h2Stream is one HTTP/2 request/response pair presented as a net.Conn: the
// request body carries bytes up, the response body carries them down. The
// gRPC and XHTTP transports both ride on it, and it is the shape the private
// HTTPS transport ("kilvater", see KILVATER-SPEC.md) would reuse.
type h2Stream struct {
	up     *io.PipeWriter
	down   io.ReadCloser
	conn   net.Conn // the underlying TLS conn, for addresses and close
	cancel context.CancelFunc

	downErr error
	resp    *http.Response
	ready   chan struct{}
}

// openH2 wraps an already-handshaked h2 connection and starts one streaming
// request to reqURL. header is sent with the request; the caller writes the
// request body through the returned stream and reads the response body back.
// method and the application headers (content-type, TE, …) are the caller's.
func openH2(ctx context.Context, conn net.Conn, method, reqURL string, header http.Header) (*h2Stream, error) {
	tr := &http2.Transport{}
	cc, err := tr.NewClientConn(conn)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(reqURL)
	if err != nil {
		return nil, err
	}
	// The stream must outlive the dial context: the switchboard cancels the
	// dial context as soon as Dial returns, but the flow runs for minutes.
	// The TLS handshake already used the dial context; from here the stream's
	// own cancel (fired by Close) governs its life.
	_ = ctx
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	var body io.Reader = pr
	if method == http.MethodGet {
		body = nil
		pr.Close()
	}
	req := (&http.Request{Method: method, URL: u, Host: u.Host, Header: header, Body: nil}).WithContext(ctx)
	if body != nil {
		req.Body = pr
	}
	s := &h2Stream{up: pw, conn: conn, cancel: cancel, ready: make(chan struct{})}
	go func() {
		resp, err := cc.RoundTrip(req)
		if err != nil {
			s.downErr = err
			close(s.ready)
			pw.CloseWithError(err)
			return
		}
		s.resp = resp
		if resp.StatusCode != http.StatusOK {
			s.downErr = errors.New("h2: the server answered " + resp.Status)
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

func (s *h2Stream) waitDown() error {
	<-s.ready
	return s.downErr
}

func (s *h2Stream) Read(p []byte) (int, error) {
	if err := s.waitDown(); err != nil {
		return 0, err
	}
	return s.down.Read(p)
}

func (s *h2Stream) Write(p []byte) (int, error) {
	if s.up == nil {
		return 0, io.ErrClosedPipe
	}
	return s.up.Write(p)
}

func (s *h2Stream) Close() error {
	if s.up != nil {
		s.up.Close()
	}
	s.cancel()
	if s.down != nil {
		s.down.Close()
	}
	return s.conn.Close()
}

func (s *h2Stream) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *h2Stream) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }
func (s *h2Stream) SetDeadline(t time.Time) error      { return nil }
func (s *h2Stream) SetReadDeadline(t time.Time) error  { return nil }
func (s *h2Stream) SetWriteDeadline(t time.Time) error { return nil }

var _ net.Conn = (*h2Stream)(nil)

// postH2 sends one complete request over conn and waits for the response,
// discarding its body. It is the one-shot upload a packet-up XHTTP chunk uses.
func postH2(ctx context.Context, conn net.Conn, reqURL string, header http.Header, body []byte) error {
	defer conn.Close()
	tr := &http2.Transport{}
	cc, err := tr.NewClientConn(conn)
	if err != nil {
		return err
	}
	u, err := url.Parse(reqURL)
	if err != nil {
		return err
	}
	req := (&http.Request{Method: http.MethodPost, URL: u, Host: u.Host, Header: header,
		Body: io.NopCloser(bytesReader(body)), ContentLength: int64(len(body))}).WithContext(ctx)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("h2: upload answered " + resp.Status)
	}
	return nil
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
