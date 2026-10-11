package wire

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/tsyrenov1987/farvater-core/kilvater"
)

type kilWire struct {
	spec  PathSpec
	key   kilvater.Key
	keyID *kilvater.KeyID // set: send v2 tags; nil: send v1 tags
	mux   *h2Mux
	pad   kilvater.PadMode // how the client shapes the frames it sends up
	now   func() time.Time
	skew  atomic.Int64 // the server's clock minus ours, from the last page fetched
}

func newKilvater(s PathSpec) (Wire, error) {
	w, err := newKilWire(s, func(ctx context.Context) (net.Conn, error) {
		return dialSecure(ctx, s, false)
	})
	if err != nil {
		return nil, err
	}
	return w, nil
}

// Connection rotation defaults for kilvater: a connection stops taking new
// streams once it is this old or has carried this many bytes, so no single
// handshake's connection is the whole tunnel in time or volume (h2Mux). The
// numbers are browser-like — a page's connections turn over in minutes — and
// loose enough not to churn handshakes under load; the governor paces a
// rotation anyway.
const (
	kilConnMaxAge   = 10 * time.Minute
	kilConnMaxBytes = 256 << 20 // 256 MiB
)

func newKilWire(s PathSpec, dial func(context.Context) (net.Conn, error)) (*kilWire, error) {
	k, err := kilvater.ParseKey(s.Key)
	if err != nil {
		return nil, err
	}
	w := &kilWire{spec: s, key: k, pad: kilvater.ParsePadMode(s.Pad), now: time.Now}
	if s.KeyID != "" {
		id, err := kilvater.ParseKeyID(s.KeyID)
		if err != nil {
			return nil, err
		}
		w.keyID = &id
	}
	const pingAfterIdle, pingTimeout = 15 * time.Second, 5 * time.Second
	if p := h2ProfileFor(s.Fingerprint); p != nil {
		w.mux = newH2Mux(shapedDial(dial, p), pingAfterIdle, pingTimeout)
		w.mux.tr = p.transport(pingAfterIdle, pingTimeout)
	} else {
		w.mux = newH2Mux(dial, pingAfterIdle, pingTimeout)
	}
	w.mux.warm = w.warm
	w.mux.maxAge, w.mux.maxBytes = kilConnMaxAge, kilConnMaxBytes
	return w, nil
}

func (w *kilWire) ID() string     { return w.spec.ID }
func (w *kilWire) Spec() PathSpec { return w.spec }

// NeedsHandshake: a connection the readLoop dropped (freeze, GOAWAY) is still
// held until the next openStream replaces it; the next Dial over it
// handshakes, so the governor must count it as one (h2Mux.needsDial).
func (w *kilWire) NeedsHandshake() bool { return w.mux.needsDial() }

func (w *kilWire) Close() error        { return w.mux.Close() }
func (w *kilWire) Refresh(t time.Time) { w.mux.refresh(t) }

// authority is the requests' :authority: the link's host parameter as given,
// else the server name, with the port when it is not 443, as a browser
// writes it.
func (w *kilWire) authority() string {
	if w.spec.HostHeader != "" {
		return w.spec.HostHeader
	}
	if w.spec.Port != 0 && w.spec.Port != 443 {
		return net.JoinHostPort(w.spec.ServerSNI(), strconv.Itoa(w.spec.Port))
	}
	return w.spec.ServerSNI()
}

// serverNow is the server's clock as the last page fetched told it.
func (w *kilWire) serverNow() time.Time {
	return w.now().Add(time.Duration(w.skew.Load()))
}

// tag makes the request tag: v2 (with the key id, verified in O(1)) when the
// link carried a key id, else v1.
func (w *kilWire) tag(path string) string {
	if w.keyID != nil {
		return kilvater.NewTagV2(*w.keyID, w.key, path, w.serverNow())
	}
	return kilvater.NewTag(w.key, path, w.serverNow())
}

func (w *kilWire) Dial(ctx context.Context) (Session, error) {
	path := w.spec.Path
	if path == "" {
		path = "/connect"
	}
	origin := "https://" + w.authority()
	u := &url.URL{Scheme: "https", Host: w.authority(), Path: path}
	// The request a script on the page makes: a streamed fetch POST.
	st, err := w.mux.openStreamFunc(ctx, http.MethodPost, u.String(), func() http.Header {
		h := http.Header{}
		h.Set("Cookie", kilvater.CookieName+"="+w.tag(path))
		h.Set("Origin", origin)
		h.Set("Referer", origin+"/")
		h.Set("Accept-Encoding", chromeAcceptEncoding)
		browserHeaders(h, "fetch")
		return h
	})
	if err != nil {
		return nil, err
	}
	return &kilSession{conn: st, pad: w.pad}, nil
}

// warmTimeout bounds the page fetch that opens a connection. Past it the
// tunnel goes on without: the page is there for looks and for the clock.
var warmTimeout = 5 * time.Second

const (
	warmPageMax  = 512 << 10 // how much of the page is read
	warmAssets   = 2         // how many of its assets are fetched
	assetTimeout = 10 * time.Second
)

// warm opens a new connection the way a browser opens a site: the page
// first, then a couple of its assets, and the tunnel request after them, as a
// script on a page that has loaded would make it, along with the favicon a
// browser asks for once a page has loaded. The page's Date gives the
// server's clock, which tags are made with from then on, so a client whose
// clock is off by more than the tag window still gets in.
func (w *kilWire) warm(ctx context.Context, cc *http2.ClientConn) {
	ctx, cancel := context.WithTimeout(ctx, warmTimeout)
	defer cancel()
	origin := "https://" + w.authority()
	h := http.Header{}
	browserHeaders(h, "navigate")
	req, err := newGet(ctx, origin+"/", h)
	if err != nil {
		return
	}
	start := time.Now()
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return
	}
	rtt := time.Since(start)
	defer resp.Body.Close()
	if d, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
		w.skew.Store(int64(d.Sub(w.now())))
	}
	var body io.Reader = resp.Body
	switch resp.Header.Get("Content-Encoding") {
	case "":
	case "gzip":
		if body, err = gzip.NewReader(resp.Body); err != nil {
			return
		}
	default:
		io.Copy(io.Discard, io.LimitReader(resp.Body, warmPageMax))
		return
	}
	page, _ := io.ReadAll(io.LimitReader(body, warmPageMax))
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		return
	}
	// Wait for the assets as the page's load would, but no longer than twice
	// what the page took: a slow asset must not hold the tunnel up. Those not
	// done by then finish in the background.
	assets := pageAssets(page, warmAssets)
	done := make(chan struct{}, len(assets))
	for _, a := range assets {
		go func() {
			fetchAsset(cc, origin, a)
			done <- struct{}{}
		}()
	}
	defer func() { go fetchAsset(cc, origin, pageAsset{"/favicon.ico", "favicon"}) }()
	limit := time.NewTimer(max(2*rtt, 200*time.Millisecond))
	defer limit.Stop()
	for range assets {
		select {
		case <-done:
		case <-limit.C:
			return
		case <-ctx.Done():
			return
		}
	}
}

type pageAsset struct{ path, kind string } // kind: a browserHeaders asset variant

var (
	assetTagRe  = regexp.MustCompile(`(?is)<(link|script|img)\b([^>]*)>`)
	assetAttrRe = regexp.MustCompile(`(?is)\b(href|src|rel)\s*=\s*["']?([^"'\s>]+)`)
)

// pageAssets lists up to n same-origin stylesheets, scripts and images of a
// page, in document order.
func pageAssets(page []byte, n int) []pageAsset {
	var out []pageAsset
	for _, m := range assetTagRe.FindAllSubmatch(page, -1) {
		if len(out) == n {
			break
		}
		attrs := map[string]string{}
		for _, a := range assetAttrRe.FindAllSubmatch(m[2], -1) {
			attrs[strings.ToLower(string(a[1]))] = string(a[2])
		}
		var a pageAsset
		switch strings.ToLower(string(m[1])) {
		case "link":
			if strings.Contains(strings.ToLower(attrs["rel"]), "stylesheet") {
				a = pageAsset{attrs["href"], "style"}
			}
		case "script":
			a = pageAsset{attrs["src"], "script"}
		case "img":
			a = pageAsset{attrs["src"], "image"}
		}
		if p, ok := sameOriginPath(a.path); ok {
			a.path = p
			out = append(out, a)
		}
	}
	return out
}

// sameOriginPath turns a link on the page into a path on its own site, or
// reports that it points elsewhere.
func sameOriginPath(ref string) (string, bool) {
	if ref == "" || strings.HasPrefix(ref, "//") {
		return "", false
	}
	u, err := url.Parse(ref)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "", false
	}
	u.Fragment = ""
	if !strings.HasPrefix(u.Path, "/") {
		u.Path = "/" + u.Path
	}
	return u.RequestURI(), true
}

func fetchAsset(cc *http2.ClientConn, origin string, a pageAsset) {
	ctx, cancel := context.WithTimeout(context.Background(), assetTimeout)
	defer cancel()
	h := http.Header{}
	h.Set("Referer", origin+"/")
	browserHeaders(h, a.kind)
	req, err := newGet(ctx, origin+a.path, h)
	if err != nil {
		return
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, warmPageMax))
	resp.Body.Close()
}

func newGet(ctx context.Context, rawURL string, h http.Header) (*http.Request, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	return (&http.Request{Method: http.MethodGet, URL: u, Host: u.Host, Header: h}).WithContext(ctx), nil
}

type kilSession struct {
	conn net.Conn
	pad  kilvater.PadMode
}

func (s *kilSession) Close() error { return s.conn.Close() }

func (s *kilSession) Run(ctx context.Context, target Target, prelude []byte, up <-chan []byte, down io.Writer, m Meter) (Outcome, error) {
	body := []byte{kilvater.NetTCP}
	body, err := kilvater.AppendAddr(body, target.String())
	if err != nil {
		s.conn.Close()
		return OutcomeError, err
	}
	// OPEN is a control frame, sent before the shaper so the idle goroutine
	// (PadHeavy) never races it; the shaper carries everything after.
	if err := kilvater.WriteFrame(s.conn, kilvater.FrameOpen, body); err != nil {
		s.conn.Close()
		return OutcomeError, err
	}
	sh := kilvater.NewShaper(s.conn, s.pad)
	defer sh.Close()
	// Vary the size of the first record we put on the wire.
	if err := sh.WritePad(); err != nil {
		s.conn.Close()
		return OutcomeError, err
	}
	if len(prelude) > 0 {
		if err := sh.WriteData(prelude); err != nil {
			s.conn.Close()
			return OutcomeError, err
		}
	}
	return runStream(ctx, s.conn, &kilFrameWriter{sh: sh}, &kilFrameReader{r: s.conn}, up, down, m)
}

type kilFrameWriter struct{ sh *kilvater.Shaper }

func (fw *kilFrameWriter) Write(p []byte) (int, error) {
	if err := fw.sh.WriteData(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

type kilFrameReader struct {
	r   io.Reader
	buf []byte
	rem []byte
}

func (fr *kilFrameReader) Read(p []byte) (int, error) {
	for len(fr.rem) == 0 {
		typ, body, err := kilvater.ReadFrame(fr.r, fr.buf)
		if err != nil {
			return 0, err
		}
		fr.buf = body[:0]
		switch typ {
		case kilvater.FrameData:
			fr.rem = body
		case kilvater.FramePad:
			continue
		case kilvater.FrameClose:
			return 0, io.EOF
		default:
			return 0, fmt.Errorf("kilvater: unexpected frame type %d", typ)
		}
	}
	n := copy(p, fr.rem)
	fr.rem = fr.rem[n:]
	return n, nil
}
