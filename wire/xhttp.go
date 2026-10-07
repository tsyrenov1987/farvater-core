package wire

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// dialXHTTP carries the tunnel over XHTTP, the way Xray's client does. Two
// shapes cover the modes a catalogue uses:
//
//   - stream-one: one full-duplex HTTP/2 request whose body is the uplink and
//     whose response body is the downlink. REALITY paths default to it.
//   - packet-up: a GET whose response is the downlink, plus one short POST per
//     uplink chunk, numbered by a sequence. Plain-TLS paths default to it.
//
// mode "auto" (and "") picks stream-one under REALITY, else packet-up.
func dialXHTTP(ctx context.Context, m *h2Mux, s PathSpec) (net.Conn, error) {
	mode := s.Mode
	if mode == "" || mode == "auto" {
		if s.Security == "reality" {
			mode = "stream-one"
		} else {
			mode = "packet-up"
		}
	}
	host := s.HostHeader
	if host == "" {
		host = s.ServerSNI()
	}
	path, query := normalizeXHTTPPath(s.Path)
	base := url.URL{Scheme: "https", Host: host, Path: path, RawQuery: query}

	switch mode {
	case "stream-one":
		h := xhttpHeaders(base.String())
		h.Set("Content-Type", "application/grpc")
		st, err := m.openStream(ctx, http.MethodPost, base.String(), h)
		if err != nil {
			return nil, err
		}
		return st, nil
	case "packet-up", "stream-up":
		return dialXHTTPPacketUp(ctx, m, base, mode == "stream-up")
	default:
		return nil, errors.New("xhttp: unsupported mode " + mode)
	}
}

// normalizeXHTTPPath splits a path?query and makes the path start and end
// with a slash, as Xray's GetNormalizedPath/Query do.
func normalizeXHTTPPath(p string) (path, query string) {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		path, query = p[:i], p[i+1:]
	} else {
		path = p
	}
	if path == "" || path[0] != '/' {
		path = "/" + path
	}
	if path[len(path)-1] != '/' {
		path += "/"
	}
	return path, query
}

// xhttpHeaders is the browser "fetch" header set plus the X-Padding that the
// server validates, placed as Xray places it by default: a query in the
// Referer header, 100–1000 'X's.
func xhttpHeaders(rawURL string) http.Header {
	h := http.Header{}
	browserHeaders(h, "fetch")
	n := 100 + mrandN(901)
	if u, err := url.Parse(rawURL); err == nil {
		u.RawQuery = "x_padding=" + strings.Repeat("X", n)
		h.Set("Referer", u.String())
	}
	return h
}

func appendXHTTPPath(base url.URL, parts ...string) string {
	p := base.Path
	for _, seg := range parts {
		if !strings.HasSuffix(p, "/") {
			p += "/"
		}
		p += seg
	}
	base.Path = p
	return base.String()
}

// dialXHTTPPacketUp runs the packet-up / stream-up shape: a GET for the
// downlink and per-chunk POSTs (or one streamed POST) for the uplink, keyed
// by a shared session id.
func dialXHTTPPacketUp(ctx context.Context, m *h2Mux, base url.URL, streamUp bool) (net.Conn, error) {
	var sid [16]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return nil, err
	}
	session := hex.EncodeToString(sid[:])

	downURL := appendXHTTPPath(base, session)
	st, err := m.openStream(ctx, http.MethodGet, downURL, xhttpHeaders(downURL))
	if err != nil {
		return nil, err
	}
	// Detach the session context from the dial context (see h2Mux.openStream):
	// the per-chunk uploads run for the whole flow, not just the dial.
	sctx, scancel := context.WithCancel(context.Background())
	c := &xhttpPacketUp{ctx: sctx, cancel: scancel, mux: m, base: base, session: session, down: st, streamUp: streamUp}
	if streamUp {
		h := xhttpHeaders(appendXHTTPPath(base, session))
		h.Set("Content-Type", "application/grpc")
		upst, err := m.openStream(ctx, http.MethodPost, appendXHTTPPath(base, session), h)
		if err != nil {
			st.Close()
			return nil, err
		}
		c.upStream = upst
	}
	return c, nil
}

// xhttpPacketUp is the client side of packet-up/stream-up: Read drains the
// downlink GET; Write sends one numbered POST per chunk (packet-up) or writes
// to the uplink stream (stream-up).
type xhttpPacketUp struct {
	ctx      context.Context
	cancel   context.CancelFunc
	mux      *h2Mux
	base     url.URL
	session  string
	down     net.Conn
	upStream net.Conn
	streamUp bool

	wmu sync.Mutex
	seq int64
}

func (c *xhttpPacketUp) Read(p []byte) (int, error) { return c.down.Read(p) }

func (c *xhttpPacketUp) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.streamUp {
		if _, err := c.upStream.Write(p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	seq := strconv.FormatInt(c.seq, 10)
	c.seq++
	reqURL := appendXHTTPPath(c.base, c.session, seq)
	h := xhttpHeaders(reqURL)
	h.Set("Content-Type", "application/grpc")
	if err := c.mux.post(c.ctx, reqURL, h, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *xhttpPacketUp) Close() error {
	c.cancel()
	if c.upStream != nil {
		c.upStream.Close()
	}
	return c.down.Close()
}

func (c *xhttpPacketUp) LocalAddr() net.Addr                { return c.down.LocalAddr() }
func (c *xhttpPacketUp) RemoteAddr() net.Addr               { return c.down.RemoteAddr() }
func (c *xhttpPacketUp) SetDeadline(t time.Time) error      { return nil }
func (c *xhttpPacketUp) SetReadDeadline(t time.Time) error  { return nil }
func (c *xhttpPacketUp) SetWriteDeadline(t time.Time) error { return nil }

var _ net.Conn = (*xhttpPacketUp)(nil)
