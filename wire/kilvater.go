package wire

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
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

	// What the last page fetch left behind, as a browser's cache would hold
	// it: later connections revalidate instead of fetching it all again.
	cacheMu sync.Mutex
	cache   map[string]validator // by path
	assets  []pageAsset          // the page's, from its last full fetch
	skew    atomic.Int64         // the server's clock minus ours, from the last page fetched

	// resumeNo is when (UnixNano) a server last showed it does not keep
	// sessions; 0 is never (kilvater_resume.go).
	resumeNo atomic.Int64
}

func newKilvater(s PathSpec) (Wire, error) {
	w, err := newKilWire(s, func(ctx context.Context) (net.Conn, error) {
		// One connection carries all the flows, so every handshake here is
		// a reconnect a filter can count: a flow's dial, a rotation's spare,
		// a resumed session all take their turn (hsgate.go).
		return dialSecurePaced(ctx, s, false)
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

	// Each connection draws its own limits within ±30% of those (7 to 13
	// minutes, 179 to 333 MiB), and the next one is made in the background
	// once it is 80% into either, so a rotation holds no stream up.
	kilConnSpread = 0.3
	kilConnAhead  = 0.8

	// A connection with nothing to read is PINGed after 15 to 25 s, drawn
	// once per path: not the same number on every client.
	kilPingAfterIdle  = 15 * time.Second
	kilPingIdleJitter = 10 * time.Second
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
	const pingTimeout = 5 * time.Second
	pingAfterIdle := kilPingAfterIdle + rand.N(kilPingIdleJitter)
	if p := h2ProfileFor(s.Fingerprint); p != nil {
		w.mux = newH2Mux(shapedDial(dial, p), pingAfterIdle, pingTimeout)
		w.mux.tr = p.transport(pingAfterIdle, pingTimeout)
	} else {
		w.mux = newH2Mux(dial, pingAfterIdle, pingTimeout)
	}
	// A connection left with no streams is closed after h2IdleClose, as on the
	// other HTTP/2 transports and as a browser drops a site it left: without
	// it an idle phone PINGs every pingAfterIdle for as long as the tunnel is
	// up, and the cellular radio never gets to sleep. The next flow dials and
	// warms a fresh one.
	w.mux.tr.IdleConnTimeout = h2IdleClose
	w.mux.warm = w.warm
	w.mux.held = w.gateHeld
	w.mux.maxAge, w.mux.maxBytes = kilConnMaxAge, kilConnMaxBytes
	w.mux.spread, w.mux.ahead = kilConnSpread, kilConnAhead
	w.joinPeers()
	return w, nil
}

func (w *kilWire) ID() string     { return w.spec.ID }
func (w *kilWire) Spec() PathSpec { return w.spec }

// NeedsHandshake: a connection the readLoop dropped (freeze, GOAWAY) is still
// held until the next openStream replaces it; the next Dial over it
// handshakes, so the governor must count it as one (h2Mux.needsDial).
func (w *kilWire) NeedsHandshake() bool { return w.mux.needsDial() }

// HandshakeHeld: the next Dial would be refused by the handshake pacing
// (PacedWire). Not while a connection past its rotation limit can still take
// the flow: the mux stays on it until a fresh one may be made.
func (w *kilWire) HandshakeHeld() bool { return w.gateHeld() && !w.mux.usable() }

func (w *kilWire) gateHeld() bool {
	return handshakes.held(w.spec.ServerSNI(), w.spec.Fingerprint)
}

func (w *kilWire) Close() error {
	w.leavePeers()
	return w.mux.Close()
}

func (w *kilWire) Refresh(t time.Time) { w.mux.refresh(t) }

// WatchConns hands the ends of the wire's connections to f (see ConnWatcher).
func (w *kilWire) WatchConns(f func(end ConnEnd, bytes int64, made time.Time)) { w.mux.onEnd = f }

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

// openTunnel opens one tunnel stream: the streamed fetch POST a script on the
// loaded page makes, carrying the auth tag in the cookie. Dial (TCP) and
// DialPacket (UDP) open it the same way; what tells them apart is the network
// byte in the OPEN frame that follows.
func (w *kilWire) openTunnel(ctx context.Context) (net.Conn, error) {
	path := w.spec.Path
	if path == "" {
		path = "/connect"
	}
	origin := "https://" + w.authority()
	u := &url.URL{Scheme: "https", Host: w.authority(), Path: path}
	return w.mux.openStreamFunc(ctx, http.MethodPost, u.String(), func() http.Header {
		h := http.Header{}
		h.Set("Cookie", kilvater.CookieName+"="+w.tag(path))
		h.Set("Origin", origin)
		h.Set("Referer", origin+"/")
		h.Set("Accept-Encoding", chromeAcceptEncoding)
		browserHeaders(h, "fetch")
		return h
	})
}

func (w *kilWire) Dial(ctx context.Context) (Session, error) {
	st, err := w.openTunnel(ctx)
	if err != nil {
		return nil, err
	}
	return &kilSession{conn: st, pad: w.pad, w: w}, nil
}

// DialPacket opens a UDP association over a tunnel stream. Kilvater binds one
// stream to one target (see kilPacketSession), which is how the switchboard
// uses a packet session: one association per app socket and destination.
func (w *kilWire) DialPacket(ctx context.Context) (PacketSession, error) {
	st, err := w.openTunnel(ctx)
	if err != nil {
		return nil, err
	}
	return &kilPacketSession{conn: st}, nil
}

var _ PacketWire = (*kilWire)(nil)

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
	w.conditional(h, "/")
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
	var assets []pageAsset
	if resp.StatusCode == http.StatusNotModified {
		// The page has not changed: its assets are the ones it had.
		w.cacheMu.Lock()
		assets = w.assets
		w.cacheMu.Unlock()
	} else if assets, err = w.readPage(resp); err != nil {
		return
	}
	// Wait for the assets as the page's load would, but no longer than twice
	// what the page took: a slow asset must not hold the tunnel up. Those not
	// done by then finish in the background.
	done := make(chan struct{}, len(assets))
	for _, a := range assets {
		go func() {
			w.fetchAsset(cc, origin, a)
			done <- struct{}{}
		}()
	}
	defer func() { go w.fetchAsset(cc, origin, pageAsset{"/favicon.ico", "favicon"}) }()
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

// validator is what a response gave to revalidate it with.
type validator struct{ etag, modified string }

// conditional adds to a request for path what the last answer to it left to
// revalidate with, as a browser asks again for what it has cached.
func (w *kilWire) conditional(h http.Header, path string) {
	w.cacheMu.Lock()
	v, ok := w.cache[path]
	w.cacheMu.Unlock()
	if !ok {
		return
	}
	if v.etag != "" {
		h.Set("If-None-Match", v.etag)
	}
	if v.modified != "" {
		h.Set("If-Modified-Since", v.modified)
	}
}

// remember keeps a 200 answer's validators for path, if it gave any.
func (w *kilWire) remember(path string, resp *http.Response) {
	if resp.StatusCode != http.StatusOK {
		return
	}
	v := validator{resp.Header.Get("ETag"), resp.Header.Get("Last-Modified")}
	if v == (validator{}) {
		return
	}
	w.cacheMu.Lock()
	if w.cache == nil {
		w.cache = map[string]validator{}
	}
	w.cache[path] = v
	w.cacheMu.Unlock()
}

// readPage reads a page answered in full and lists the assets to fetch.
func (w *kilWire) readPage(resp *http.Response) ([]pageAsset, error) {
	var err error
	var body io.Reader = resp.Body
	switch resp.Header.Get("Content-Encoding") {
	case "":
	case "gzip":
		if body, err = gzip.NewReader(resp.Body); err != nil {
			return nil, err
		}
	default:
		io.Copy(io.Discard, io.LimitReader(resp.Body, warmPageMax))
		return nil, errors.New("kilvater: page encoding not read")
	}
	page, _ := io.ReadAll(io.LimitReader(body, warmPageMax))
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		return nil, errors.New("kilvater: not a page")
	}
	assets := pageAssets(page, warmAssets)
	w.remember("/", resp)
	w.cacheMu.Lock()
	w.assets = assets
	w.cacheMu.Unlock()
	return assets, nil
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

func (w *kilWire) fetchAsset(cc *http2.ClientConn, origin string, a pageAsset) {
	ctx, cancel := context.WithTimeout(context.Background(), assetTimeout)
	defer cancel()
	h := http.Header{}
	h.Set("Referer", origin+"/")
	browserHeaders(h, a.kind)
	w.conditional(h, a.path)
	req, err := newGet(ctx, origin+a.path, h)
	if err != nil {
		return
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return
	}
	w.remember(a.path, resp)
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
	w    *kilWire // nil: the flow is never resumed
}

func (s *kilSession) Close() error { return s.conn.Close() }

func (s *kilSession) Run(ctx context.Context, target Target, prelude []byte, up <-chan []byte, down io.Writer, m Meter) (Outcome, error) {
	body := []byte{kilvater.NetTCP}
	body, err := kilvater.AppendAddr(body, target.String())
	if err != nil {
		s.conn.Close()
		return OutcomeError, err
	}
	if s.w != nil && s.w.resumeWanted() {
		return s.runResumable(ctx, body, prelude, up, down, m)
	}
	// OPEN, what the app already sent and a PAD go out as one record, so the
	// OPEN's size (the length of the target's name) never shows on its own.
	sh := kilvater.NewShaper(s.conn, s.pad)
	defer sh.Close()
	if err := sh.WriteOpening(kilvater.AppendFrame(nil, kilvater.FrameOpen, body), prelude); err != nil {
		s.conn.Close()
		return OutcomeError, kilRefusal(err)
	}
	fr := &kilFrameReader{r: s.conn}
	out, err := runStream(ctx, s.conn, &kilFrameWriter{sh: sh}, fr, up, down, m)
	if err == nil && fr.refused {
		// The node answered, and said it could not reach the target: the flow
		// ends as before, and the error tells the caller the path is not to blame.
		return out, ErrTargetUnreachable
	}
	return out, kilRefusal(err)
}

// runResumable is Run for a flow that names a session in its OPEN, so that
// it can go on over another stream if this one is lost.
func (s *kilSession) runResumable(ctx context.Context, body, prelude []byte, up <-chan []byte, down io.Writer, m Meter) (Outcome, error) {
	sh := kilvater.NewShaper(s.conn, s.pad)
	rs, err := newKilResume(s.w, s.conn, sh)
	if err != nil {
		sh.Close()
		s.conn.Close()
		return OutcomeError, err
	}
	body = kilvater.AppendSessionExt(body, rs.sid)
	rs.up.Append(prelude)
	if err := sh.WriteOpening(kilvater.AppendFrame(nil, kilvater.FrameOpen, body), prelude); err != nil {
		rs.Close()
		return OutcomeError, kilRefusal(err)
	}
	out, err := runStream(ctx, rs, rs, rs, up, down, m)
	if err == nil && rs.refused {
		return out, ErrTargetUnreachable
	}
	return out, kilRefusal(err)
}

// ErrAccessRefused is a stream the node answered with its plain site instead
// of a tunnel. The node gives every request it will not serve the same answer
// and never says why, so the cause is one of: the key is revoked or not on the
// node's list, the key is over its stream or volume limit, or this device's
// clock is too far off for the mark to be fresh. The path itself carried the
// request and the answer.
var ErrAccessRefused = errors.New("wire: the node did not accept the key (revoked, not on its list, over its limit, or the clock is off)")

// kilRefusal turns the mux's "answered 404" into ErrAccessRefused, keeping the
// status in the text; any other error passes as it is.
func kilRefusal(err error) error {
	var se *H2StatusError
	if errors.As(err, &se) {
		return fmt.Errorf("%w: answered %s", ErrAccessRefused, se.Status)
	}
	return err
}

// ErrTargetUnreachable comes with OutcomeRemoteFin from a transport whose
// server said, before any byte of an answer, that it could not reach the
// target. The path carried the question and the server's reply, so the
// failure is the destination's (or the node's route to it), not the path's.
var ErrTargetUnreachable = errors.New("wire: the server could not reach the target")

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

	got     bool // a DATA frame has arrived
	refused bool // CLOSE with a failure code came before any DATA
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
			fr.got = true
		case kilvater.FramePad:
			continue
		case kilvater.FrameClose:
			if !fr.got && len(body) > 0 && body[0] != kilvater.CloseOK {
				fr.refused = true
			}
			return 0, io.EOF
		default:
			if typ > kilvater.FrameClose {
				continue // a frame type from a newer server: skip it, like PAD
			}
			return 0, fmt.Errorf("kilvater: unexpected frame type %d", typ)
		}
	}
	n := copy(p, fr.rem)
	fr.rem = fr.rem[n:]
	return n, nil
}

// errKilUDPTarget is returned when a second target is sent on a stream already
// bound to one. One stream carries one UDP target; a different destination gets
// its own association. The switchboard opens one per socket and destination, so
// this never fires there.
var errKilUDPTarget = errors.New("kilvater: one stream carries one UDP target")

// kilPacketSession carries one app UDP socket's datagrams over one tunnel
// stream. The first datagram's target is named in OPEN and fixes the
// association for its life; the server dials a connected socket to it, which
// both pins the target and gives UDP the same public-address check as TCP. Each
// datagram is its own frame, so message boundaries survive the tunnel. Unlike
// trojan or XUDP, a stream is not multiplexed across targets.
type kilPacketSession struct {
	conn   net.Conn
	opened bool
	target Target
}

func (s *kilPacketSession) Close() error { return s.conn.Close() }

// WritePacket sends one datagram. The contract gives it one writer at a time,
// so opened/target need no lock.
func (s *kilPacketSession) WritePacket(p []byte, target Target) error {
	if !s.opened {
		body := []byte{kilvater.NetUDP}
		body, err := kilvater.AppendAddr(body, target.String())
		if err != nil {
			return err
		}
		// OPEN, a PAD and the first datagram go out as one record, so the OPEN's
		// size (the length of the target's name) never shows on its own.
		b := kilvater.AppendFrame(nil, kilvater.FrameOpen, body)
		b = kilvater.AppendFrame(b, kilvater.FramePad, make([]byte, 16+rand.IntN(256)))
		if len(p) <= kilvater.MaxFrame {
			b = kilvater.AppendFrame(b, kilvater.FrameDgram, p)
		}
		s.opened, s.target = true, target
		_, err = s.conn.Write(b)
		return err
	} else if target != s.target {
		return errKilUDPTarget
	}
	if len(p) > kilvater.MaxFrame {
		return nil // too large to frame; drop it, as any UDP datagram may be dropped
	}
	return kilvater.WriteFrame(s.conn, kilvater.FrameDgram, p)
}

// ReadPacket returns the next datagram. The source is the zero Target: the
// socket is connected to the one target, so replies can only come from it, and
// the switchboard fills the reply address in from the association's target.
func (s *kilPacketSession) ReadPacket() ([]byte, Target, error) {
	for {
		typ, body, err := kilvater.ReadFrame(s.conn, nil)
		if err != nil {
			return nil, Target{}, err
		}
		switch typ {
		case kilvater.FrameDgram:
			return body, Target{}, nil
		case kilvater.FramePad:
			continue
		case kilvater.FrameClose:
			return nil, Target{}, io.EOF
		default:
			if typ > kilvater.FrameClose {
				continue // a frame type from a newer server: skip it, like PAD
			}
			return nil, Target{}, fmt.Errorf("kilvater: unexpected frame type %d", typ)
		}
	}
}
