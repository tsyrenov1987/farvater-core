package wire

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/tsyrenov1987/farvater-core/kilvater"
	"golang.org/x/net/http2"
)

// Split mode (mode=split / split-post on the link) carries a tunnel stream
// as separate requests, for a path that runs through a CDN: one long GET
// brings the downlink, and the uplink goes up in pieces, each its own short
// request, in GET headers or in POST bodies (kilvater/split.go has the wire
// format). Both directions are sealed end to end, since the CDN's edge ends
// TLS. The frames inside are those of a POST stream, so kilSession, resume
// and the server's flow code run over a split stream unchanged.

const (
	// Per uplink piece: the raw bytes a GET carries in its headers, cut into
	// headers of splitHeaderChars base64 characters, and what a POST carries.
	// Yandex Cloud CDN passed 64 KB of request headers to the origin, 16
	// headers of 4000 characters or one of 32000 (measured 18.11); a piece
	// takes 54 KB of base64 in 14 headers, under that with the rest of the
	// request. Through that CDN 24 KB pieces, four at a time, went up at
	// 6 Mbit/s and 40 KB ones, twelve at a time, at 15-19 (18.11, from NSK).
	splitGetPiece    = 40 << 10
	splitHeaderChars = 4 << 10
	// CDN Timeweb's edge ends an h2 connection with GOAWAY after about 200
	// requests (measured 19.11 from NSK: 64 KB pieces hit it every 12 MB);
	// 256 KB ones carry 50 MB in as many, past the mux's own turnover
	// (kilSplitConnMaxBytes). Twelve in flight stay under the server's 4 MB
	// of pieces held out of order, and each under its 1 MB a piece.
	splitPostPiece = 256 << 10

	// Pieces in flight at once; the server puts them back in order. Sixteen
	// went no faster than twelve.
	splitInFlight = 12
	// What Write holds before it blocks, waiting for pieces to go up.
	splitUpBuffer = 1 << 20
	// A piece that gets no answer in this long breaks the stream.
	splitPieceTimeout = 30 * time.Second
	// The wait before a piece the server never took goes again (h2Unsent).
	splitPieceRetry = 200 * time.Millisecond
)

// openSplit opens one split tunnel stream: it starts the downlink GET and
// returns the stream at once; the uplink requests go out as it is written.
func (w *kilWire) openSplit(ctx context.Context) (net.Conn, error) {
	var raw [16]byte
	rand.Read(raw[:])
	sid := base64.RawURLEncoding.EncodeToString(raw[:])
	base := w.spec.Path
	if base == "" {
		base = "/connect"
	}
	base = trimSlash(base) + "/" + sid
	c := &splitConn{w: w, base: base, sid: raw[:], post: w.spec.Mode == "split-post", ext: w.spec.SplitExt}
	c.cond = sync.NewCond(&c.mu)
	c.sw = kilvater.NewSealWriter(splitBuf{c}, w.key, c.sid, kilvater.SealUp)
	c.ctx, c.cancel = context.WithCancel(context.Background())
	down, err := w.mux.openStreamFunc(ctx, http.MethodGet, w.splitURL(base+"/d"+c.ext), func() http.Header {
		return w.splitHeader(base + "/d" + c.ext)
	})
	if err != nil {
		c.cancel()
		return nil, err
	}
	c.down = down
	c.rd = kilvater.NewSealReader(down, w.key, c.sid, kilvater.SealDown)
	go c.sendLoop()
	return c, nil
}

func trimSlash(p string) string {
	for len(p) > 0 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	return p
}

func (w *kilWire) splitURL(path string) string {
	return (&url.URL{Scheme: "https", Host: w.authority(), Path: path}).String()
}

// splitHeader is a split request's headers: the tag over its own path, and
// what a page's fetch would send.
func (w *kilWire) splitHeader(path string) http.Header {
	origin := "https://" + w.authority()
	h := http.Header{}
	h.Set("Cookie", kilvater.CookieName+"="+w.tag(path))
	h.Set("Origin", origin)
	h.Set("Referer", origin+"/")
	h.Set("Accept-Encoding", chromeAcceptEncoding)
	browserHeaders(h, "fetch")
	return h
}

type splitConn struct {
	w    *kilWire
	base string
	sid  []byte
	post bool
	ext  string // ".ts" etc. after every path (spec.SplitExt), or ""

	down net.Conn
	rd   *kilvater.SealReader
	sw   *kilvater.SealWriter

	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte // sealed, not yet sent
	fin    bool   // the uplink is to end after buf
	closed bool
	err    error
}

// splitBuf is where the seal writer puts records: the uplink buffer.
type splitBuf struct{ c *splitConn }

func (b splitBuf) Write(p []byte) (int, error) {
	c := b.c
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.buf) >= splitUpBuffer && c.err == nil && !c.closed {
		c.cond.Wait()
	}
	if c.err != nil {
		return 0, c.err
	}
	if c.closed || c.fin {
		return 0, net.ErrClosed
	}
	c.buf = append(c.buf, p...)
	c.cond.Broadcast()
	return len(p), nil
}

// rollDue reports that the connection the downlink rides has carried enough
// that the CDN may cut it soon: the flow on this stream should move to a new
// one (kilResume.roll), which the mux puts on a fresh connection.
func (c *splitConn) rollDue() bool {
	b, ok := c.down.(interface{ connBytes() int64 })
	return ok && b.connBytes() >= kilSplitRollBytes.Load()
}

func (c *splitConn) Read(p []byte) (int, error) { return c.rd.Read(p) }

func (c *splitConn) Write(p []byte) (int, error) { return c.sw.Write(p) }

// CloseWrite ends the uplink: the last piece carries the end mark.
func (c *splitConn) CloseWrite() error {
	c.mu.Lock()
	c.fin = true
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}

func (c *splitConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	// Whatever is still buffered goes up with the end mark, so the server's
	// side of the flow ends rather than waiting for its idle limit.
	c.fin = true
	c.closed = true
	c.cond.Broadcast()
	c.mu.Unlock()
	err := c.down.Close()
	go func() {
		time.Sleep(splitPieceTimeout)
		c.cancel()
	}()
	return err
}

func (c *splitConn) fail(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.cond.Broadcast()
	c.mu.Unlock()
	c.down.Close()
	c.cancel()
}

// sendLoop cuts the buffer into pieces and sends them, up to splitInFlight at
// once. A piece goes as soon as there is anything to send; while the slots
// are full, more gathers, so pieces grow with the rate.
func (c *splitConn) sendLoop() {
	max := splitGetPiece
	if c.post {
		max = splitPostPiece
	}
	slots := make(chan struct{}, splitInFlight)
	var wg sync.WaitGroup
	defer func() {
		wg.Wait()
		c.cancel()
	}()
	for seq := uint64(0); ; seq++ {
		select {
		case slots <- struct{}{}:
		case <-c.ctx.Done():
			return
		}
		c.mu.Lock()
		for len(c.buf) == 0 && !c.fin && c.err == nil {
			c.cond.Wait()
		}
		if c.err != nil {
			c.mu.Unlock()
			return
		}
		n := min(len(c.buf), max)
		piece := bytes.Clone(c.buf[:n])
		c.buf = c.buf[n:]
		last := c.fin && len(c.buf) == 0
		c.cond.Broadcast()
		c.mu.Unlock()
		wg.Add(1)
		go func(seq uint64) {
			defer wg.Done()
			defer func() { <-slots }()
			if err := c.send(seq, piece, last); err != nil {
				c.fail(err)
			}
		}(seq)
		if last {
			return
		}
	}
}

// send puts one piece up. A piece the server never took (its connection
// ended with GOAWAY before it, or a new connection's handshake was held back)
// goes again on another: the server keeps pieces by seq and drops repeats, so
// the stream goes on rather than breaking at every turnover of the edge.
func (c *splitConn) send(seq uint64, piece []byte, last bool) error {
	ctx, cancel := context.WithTimeout(c.ctx, splitPieceTimeout)
	defer cancel()
	for {
		err := c.sendOnce(ctx, seq, piece, last)
		if err == nil || !h2Unsent(err) {
			return err
		}
		t := time.NewTimer(splitPieceRetry)
		select {
		case <-ctx.Done():
			t.Stop()
			return err
		case <-t.C:
		}
	}
}

func (c *splitConn) sendOnce(ctx context.Context, seq uint64, piece []byte, last bool) error {
	path := c.base + "/u/" + strconv.FormatUint(seq, 10) + c.ext
	u, err := url.Parse(c.w.splitURL(path))
	if err != nil {
		return err
	}
	cc, _, err := c.w.mux.client(ctx)
	if err != nil {
		return err
	}
	h := c.w.splitHeader(path)
	if last {
		h.Set(kilvater.SplitFinHeader, "1")
	}
	req := &http.Request{Method: http.MethodGet, URL: u, Host: u.Host, Header: h}
	if c.post {
		req.Method = http.MethodPost
		req.Body = io.NopCloser(bytes.NewReader(piece))
		req.ContentLength = int64(len(piece))
	} else {
		enc := base64.RawURLEncoding.EncodeToString(piece)
		for i := 0; len(enc) > 0; i++ {
			k := min(len(enc), splitHeaderChars)
			h.Set(kilvater.SplitHeader+strconv.Itoa(i), enc[:k])
			enc = enc[k:]
		}
	}
	resp, err := cc.RoundTrip(req.WithContext(ctx))
	if err != nil {
		return err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return &H2StatusError{Code: resp.StatusCode, Status: resp.Status}
	}
	return nil
}

func (c *splitConn) LocalAddr() net.Addr                { return c.down.LocalAddr() }
func (c *splitConn) RemoteAddr() net.Addr               { return c.down.RemoteAddr() }
func (c *splitConn) SetDeadline(t time.Time) error      { return nil }
func (c *splitConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *splitConn) SetWriteDeadline(t time.Time) error { return nil }

// h2Unsent reports an error after which the request certainly did not reach
// the server, so it may go again: the connection's GOAWAY came before the
// stream (x/net/http2 names these errors but does not export them), the
// stream was refused, or a new connection's handshake was held back.
func h2Unsent(err error) bool {
	if errors.Is(err, ErrHandshakePaced) {
		return true
	}
	var se http2.StreamError
	if errors.As(err, &se) && se.Code == http2.ErrCodeRefusedStream {
		return true
	}
	switch err.Error() {
	case "http2: Transport received Server's graceful shutdown GOAWAY",
		"http2: client conn not usable":
		return true
	}
	return false
}
