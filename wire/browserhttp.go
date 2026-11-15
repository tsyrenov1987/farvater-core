package wire

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"

	utls "github.com/refraction-networking/utls"
)

// BrowserTransport is an http.RoundTripper for the core's own requests to a
// server (the catalogue and the like) whose connection reads like Chrome's
// from outside: the ClientHello is the one the paths send for fp=chrome
// (chromeAutoSpec), and when the server picks HTTP/2 the frames are put into
// Chrome's form by the same shaper (chromeH2). Go's own TLS would name the
// client in every such request, the same rare ClientHello every 30 minutes to
// the same addresses.
//
// Each request gets a connection of its own, closed with the response body:
// the requests it serves are one-off.
type BrowserTransport struct {
	// Dial opens the connection to host:port; nil dials directly, as Go's
	// http.Transport would (the system's routing, no SocketControl).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// RootCAs, when set, are the roots the server's certificate is checked
	// against instead of the system's (tests).
	RootCAs *x509.CertPool
}

func (t *BrowserTransport) dial(ctx context.Context, addr string) (net.Conn, error) {
	if t.Dial != nil {
		return t.Dial(ctx, "tcp", addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

// RoundTrip sends req over a fresh connection. A plain http:// URL goes out
// as Go's http.Transport sends it, over the same Dial.
func (t *BrowserTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil {
		return nil, errors.New("browser transport: no URL")
	}
	addr := req.URL.Host
	switch req.URL.Scheme {
	case "http":
		tr := &http.Transport{
			DialContext:       func(ctx context.Context, _, a string) (net.Conn, error) { return t.dial(ctx, a) },
			DisableKeepAlives: true,
			Proxy:             nil,
		}
		return closeAfter(tr.RoundTrip(req))(tr.CloseIdleConnections)
	case "https":
	default:
		return nil, errors.New("browser transport: unsupported scheme " + strconv.Quote(req.URL.Scheme))
	}
	host := req.URL.Hostname()
	if req.URL.Port() == "" {
		addr = net.JoinHostPort(host, "443")
	}
	ctx := req.Context()
	raw, err := t.dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	cfg := &utls.Config{ServerName: host, RootCAs: t.RootCAs, ClientSessionCache: tlsSessions}
	u, err := uClient(raw, cfg, "chrome")
	if err != nil {
		raw.Close()
		return nil, err
	}
	if err := u.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	if u.ConnectionState().NegotiatedProtocol == "h2" {
		cc, err := chromeH2.transport(0, 0).NewClientConn(newH2Shaper(u, chromeH2))
		if err != nil {
			u.Close()
			return nil, err
		}
		resp, err := cc.RoundTrip(req)
		if err != nil {
			cc.Close()
			return nil, err
		}
		resp.Body = &bodyCloser{ReadCloser: resp.Body, after: func() { cc.Close() }}
		return resp, nil
	}
	// HTTP/1.1 on the connection made here: Go's http.Transport writes the
	// request, given this connection as the one TLS dial it may make.
	var once sync.Once
	tr := &http.Transport{
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			c := net.Conn(nil)
			once.Do(func() { c = u })
			if c == nil {
				return nil, errors.New("browser transport: one connection per request")
			}
			return c, nil
		},
		DisableKeepAlives: true,
		Proxy:             nil,
	}
	resp, err := tr.RoundTrip(req)
	once.Do(func() {}) // a request that never dialed must not leave u open
	if err != nil {
		u.Close()
		return nil, err
	}
	resp.Body = &bodyCloser{ReadCloser: resp.Body, after: func() { u.Close(); tr.CloseIdleConnections() }}
	return resp, nil
}

// closeAfter wraps a response's body so that closing it also runs done.
func closeAfter(resp *http.Response, err error) func(done func()) (*http.Response, error) {
	return func(done func()) (*http.Response, error) {
		if err != nil {
			done()
			return nil, err
		}
		resp.Body = &bodyCloser{ReadCloser: resp.Body, after: done}
		return resp, nil
	}
}

type bodyCloser struct {
	io.ReadCloser
	after func()
	once  sync.Once
}

func (b *bodyCloser) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.after)
	return err
}
