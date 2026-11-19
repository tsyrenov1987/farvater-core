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
	if s.XQuery {
		path, query = splitXHTTPPath(s.Path)
	}
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
		if s.XQuery {
			if mode != "packet-up" {
				return nil, errors.New("xhttp: xquery needs mode packet-up")
			}
			return dialXHTTPQuery(ctx, m, base, s.XQ)
		}
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

// splitXHTTPPath splits a path?query and only makes the path start with a
// slash: the xquery shape keeps a file path as it is.
func splitXHTTPPath(p string) (path, query string) {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		path, query = p[:i], p[i+1:]
	} else {
		path = p
	}
	if path == "" || path[0] != '/' {
		path = "/" + path
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

// xqDefaults fills the knobs a link left out with what the nodes use today:
// xhttpSettings sessionPlacement/seqPlacement/xPaddingPlacement "query",
// sessionKey "sid", seqKey "page", xPaddingKey "t", xPaddingMethod
// "tokenish", obfs mode on, uplinkHTTPMethod POST, uplinkDataPlacement body.
func xqDefaults(x XQuerySpec) XQuerySpec {
	if x.SessionKey == "" {
		x.SessionKey = "sid"
	}
	if x.SeqKey == "" {
		x.SeqKey = "page"
	}
	if x.PadKey == "" {
		x.PadKey = "t"
	}
	if x.PadMax == 0 {
		// 200–600 base62 characters: a base62 character takes 5 to 7
		// Huffman bits, so the node's 100–1000-byte check sees 125–525.
		x.PadMin, x.PadMax = 200, 600
	}
	if x.ContentType == "" {
		x.ContentType = "application/octet-stream"
	}
	if x.ChunkKiB == 0 {
		x.ChunkKiB = 256
	}
	if x.InFlight == 0 {
		x.InFlight = 4
	}
	return x
}

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func randBase62(n int) string {
	b := make([]byte, n)
	var r [1]byte
	for i := range b {
		for {
			if _, err := rand.Read(r[:]); err != nil {
				r[0] = byte(mrandN(248))
			}
			if r[0] < 248 { // 248 = 4*62: no modulo bias
				break
			}
		}
		b[i] = base62[int(r[0])%62]
	}
	return string(b)
}

// url is base with the session (and the sequence, for an upload) and a fresh
// padding added to its query.
func (x XQuerySpec) url(base url.URL, session, seq string) string {
	q := base.Query()
	q.Set(x.SessionKey, session)
	if seq != "" {
		q.Set(x.SeqKey, seq)
	}
	if x.PadKey != "-" {
		q.Set(x.PadKey, randBase62(x.PadMin+mrandN(x.PadMax-x.PadMin+1)))
	}
	base.RawQuery = q.Encode()
	return base.String()
}

// xqHeaders is the browser "fetch" set alone: no Referer padding, which CDN
// filters read as a probe.
func xqHeaders() http.Header {
	h := http.Header{}
	browserHeaders(h, "fetch")
	return h
}

// dialXHTTPQuery runs packet-up in the xquery shape: a GET for the downlink
// and numbered POSTs for the uplink, the session and sequence in the query.
func dialXHTTPQuery(ctx context.Context, m *h2Mux, base url.URL, x XQuerySpec) (net.Conn, error) {
	x = xqDefaults(x)
	var sid [16]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return nil, err
	}
	session := hex.EncodeToString(sid[:])
	st, err := m.openStream(ctx, http.MethodGet, x.url(base, session, ""), xqHeaders())
	if err != nil {
		return nil, err
	}
	sctx, scancel := context.WithCancel(context.Background())
	c := &xhttpQuery{ctx: sctx, cancel: scancel, mux: m, base: base, x: x, session: session, down: st,
		slots: make(chan struct{}, x.InFlight)}
	c.cond = sync.NewCond(&c.mu)
	go c.sendLoop()
	return c, nil
}

// xhttpQuery is the client side of the xquery shape. Write queues bytes; one
// loop cuts them into POSTs of up to ChunkKiB, numbers them in order and
// keeps up to InFlight of them going at once (the node reorders by number).
// A POST through a CDN costs a round trip, so one at a time caps the uplink
// at a chunk per RTT.
type xhttpQuery struct {
	ctx     context.Context
	cancel  context.CancelFunc
	mux     *h2Mux
	base    url.URL
	x       XQuerySpec
	session string
	down    net.Conn
	slots   chan struct{}

	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	err    error
	closed bool
}

func (c *xhttpQuery) Read(p []byte) (int, error) { return c.down.Read(p) }

// Write blocks while more than two chunks wait unsent: the caller feels the
// uplink's pace instead of filling memory.
func (c *xhttpQuery) Write(p []byte) (int, error) {
	limit := 2 * c.x.ChunkKiB << 10
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.buf) >= limit && c.err == nil && !c.closed {
		c.cond.Wait()
	}
	if c.err != nil {
		return 0, c.err
	}
	if c.closed {
		return 0, net.ErrClosed
	}
	c.buf = append(c.buf, p...)
	c.cond.Broadcast()
	return len(p), nil
}

func (c *xhttpQuery) sendLoop() {
	max := c.x.ChunkKiB << 10
	for seq := int64(0); ; seq++ {
		c.mu.Lock()
		for len(c.buf) == 0 && c.err == nil && !c.closed {
			c.cond.Wait()
		}
		if c.err != nil || c.closed {
			c.mu.Unlock()
			return
		}
		n := min(len(c.buf), max)
		chunk := make([]byte, n)
		copy(chunk, c.buf)
		c.buf = append(c.buf[:0], c.buf[n:]...)
		c.cond.Broadcast()
		c.mu.Unlock()

		select {
		case c.slots <- struct{}{}:
		case <-c.ctx.Done():
			return
		}
		go func(seq int64, chunk []byte) {
			defer func() { <-c.slots }()
			h := xqHeaders()
			h.Set("Content-Type", c.x.ContentType)
			err := c.mux.post(c.ctx, c.x.url(c.base, c.session, strconv.FormatInt(seq, 10)), h, chunk)
			if err != nil {
				c.mu.Lock()
				if c.err == nil && !c.closed {
					c.err = err
				}
				c.cond.Broadcast()
				c.mu.Unlock()
				c.down.Close() // a lost chunk breaks the stream: end the flow
			}
		}(seq, chunk)
	}
}

func (c *xhttpQuery) Close() error {
	c.mu.Lock()
	c.closed = true
	c.cond.Broadcast()
	c.mu.Unlock()
	c.cancel()
	return c.down.Close()
}

func (c *xhttpQuery) LocalAddr() net.Addr                { return c.down.LocalAddr() }
func (c *xhttpQuery) RemoteAddr() net.Addr               { return c.down.RemoteAddr() }
func (c *xhttpQuery) SetDeadline(t time.Time) error      { return nil }
func (c *xhttpQuery) SetReadDeadline(t time.Time) error  { return nil }
func (c *xhttpQuery) SetWriteDeadline(t time.Time) error { return nil }

var _ net.Conn = (*xhttpQuery)(nil)
