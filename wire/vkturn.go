package wire

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tsyrenov1987/farvater-core/vkturn"
)

// A vkturn:// link is an ordinary path whose TCP connection rides VK's call
// relays (TURN) to the node, where the relays are let through and the node is
// not:
//
//	vkturn://<psk hex>@<node ip>:<port>?t=<target>&c=<creds>&cu=<creds url>&inner=<link>#name
//
// inner is the path itself (base64url of a vless://, trojan://, vmess:// or
// kilvater:// link); its host and port are not dialed. The node's vkturn
// server hands each stream to t ("host:port", default 127.0.0.1:2090), the
// inner link's inbound. c is the base64url of a JSON list of {address,
// username, password}: one entry per relay allocation. VK's credentials last
// hours, so cu, an https URL, answers {"creds":[...]} with fresh ones; the
// core fetches it over the path itself while the old ones still work.

// TURNSpec is what a vkturn:// link adds to its inner path.
type TURNSpec struct {
	Server   string // the node's vkturn server, "ip:port"
	PSK      []byte
	Creds    []vkturn.Creds
	Target   string
	CredsURL string
}

func parseVKTurn(raw string) (PathSpec, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return PathSpec{}, err
	}
	if u.User == nil {
		return PathSpec{}, errors.New("vkturn: missing key")
	}
	psk, err := hex.DecodeString(u.User.Username())
	if err != nil || len(psk) != 32 {
		return PathSpec{}, errors.New("vkturn: key must be 64 hex")
	}
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		return PathSpec{}, fmt.Errorf("vkturn: host:port: %w", err)
	}
	q := u.Query()
	inner, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(q.Get("inner"), "="))
	if err != nil {
		return PathSpec{}, errors.New("vkturn: inner link is not base64url")
	}
	if l := strings.ToLower(string(inner)); !strings.HasPrefix(l, "vless://") && !strings.HasPrefix(l, "trojan://") &&
		!strings.HasPrefix(l, "vmess://") && !strings.HasPrefix(l, "kilvater://") {
		return PathSpec{}, errors.New("vkturn: inner link must be vless, trojan, vmess or kilvater")
	}
	spec, err := ParseURI(string(inner))
	if err != nil {
		return PathSpec{}, fmt.Errorf("vkturn: inner: %w", err)
	}
	cj, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(q.Get("c"), "="))
	if err != nil {
		return PathSpec{}, errors.New("vkturn: creds are not base64url")
	}
	var creds []vkturn.Creds
	if err := json.Unmarshal(cj, &creds); err != nil || len(creds) == 0 {
		return PathSpec{}, errors.New("vkturn: no creds")
	}
	t := &TURNSpec{Server: u.Host, PSK: psk, Creds: creds, Target: first(q.Get("t"), "127.0.0.1:2090")}
	if cu := q.Get("cu"); cu != "" {
		if p, err := url.Parse(cu); err != nil || p.Scheme != "https" || p.Host == "" {
			return PathSpec{}, errors.New("vkturn: creds url must be https")
		}
		t.CredsURL = cu
	}
	spec.TURN = t
	if f, err := url.PathUnescape(u.Fragment); err == nil && f != "" {
		spec.ID = f
	} else {
		spec.ID = u.Host
	}
	return spec, nil
}

// One tunnel per node and key carries every flow of the paths that name it.
var turnTunnels = struct {
	sync.Mutex
	m map[string]*turnEntry
}{m: map[string]*turnEntry{}}

type turnEntry struct {
	mu        sync.Mutex
	server    string
	psk       []byte
	creds     []vkturn.Creds // the freshest seen: from a link or a fetch
	tun       *vkturn.Tunnel
	lastUse   time.Time
	fetching  bool
	lastFetch time.Time
}

// Tunnels idle this long close; the next flow opens a fresh one.
const turnIdle = 90 * time.Second

// Creds are fetched when the soonest expires within turnRefreshBefore, at most
// once per turnFetchEvery. VK hands out credentials that last 8 hours and the
// provider renews its pool every 4, so what it hands out has 4 hours or more.
const (
	turnRefreshBefore = 3 * time.Hour
	turnFetchEvery    = 10 * time.Minute
)

func turnEntryFor(t *TURNSpec) *turnEntry {
	key := t.Server + "|" + hex.EncodeToString(t.PSK)
	turnTunnels.Lock()
	defer turnTunnels.Unlock()
	e := turnTunnels.m[key]
	if e == nil {
		e = &turnEntry{server: t.Server, psk: t.PSK}
		turnTunnels.m[key] = e
	}
	e.offer(t.Creds)
	return e
}

// offer keeps creds when they outlast the ones held.
func (e *turnEntry) offer(creds []vkturn.Creds) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(creds) == 0 {
		return
	}
	if len(e.creds) == 0 || vkturn.Expiry(creds).After(vkturn.Expiry(e.creds)) {
		e.creds = creds
	}
}

// tunnel returns the open tunnel, opening one if there is none.
func (e *turnEntry) tunnel(ctx context.Context) (*vkturn.Tunnel, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastUse = time.Now()
	if e.tun != nil && !e.tun.Closed() {
		return e.tun, nil
	}
	if e.tun != nil {
		e.tun.Close()
		e.tun = nil
	}
	t, err := vkturn.Open(ctx, vkturn.Config{Server: e.server, PSK: e.psk, Creds: e.creds})
	if err != nil {
		return nil, err
	}
	e.tun = t
	go e.reap(t)
	return t, nil
}

// reap closes t once no flow has used it for turnIdle, so an unused path
// holds no relay allocations.
func (e *turnEntry) reap(t *vkturn.Tunnel) {
	tk := time.NewTicker(turnIdle / 3)
	defer tk.Stop()
	for range tk.C {
		e.mu.Lock()
		if e.tun != t || t.Closed() {
			e.mu.Unlock()
			return
		}
		if t.Streams() == 0 && time.Since(e.lastUse) > turnIdle {
			t.Close()
			e.tun = nil
			e.mu.Unlock()
			return
		}
		e.mu.Unlock()
	}
}

// dialTURN opens the path's TCP connection as a stream of the node's tunnel.
func dialTURN(ctx context.Context, s PathSpec) (net.Conn, error) {
	e := turnEntryFor(s.TURN)
	var c net.Conn
	for try := 0; try < 2; try++ {
		t, err := e.tunnel(ctx)
		if err != nil {
			return nil, err
		}
		if c, err = t.Dial(ctx, s.TURN.Target); err == nil {
			break
		}
		if !t.Closed() || try == 1 {
			return nil, err
		}
	}
	e.maybeFetch(s)
	return &recordConn{Conn: &turnConn{Conn: c, e: e}}, nil
}

// turnConn counts as use until it closes.
type turnConn struct {
	net.Conn
	e    *turnEntry
	once sync.Once
}

func (c *turnConn) Close() error {
	c.once.Do(func() {
		c.e.mu.Lock()
		c.e.lastUse = time.Now()
		c.e.mu.Unlock()
	})
	return c.Conn.Close()
}

// maybeFetch starts a fetch of fresh creds when the held ones run out soon.
func (e *turnEntry) maybeFetch(s PathSpec) {
	if s.TURN.CredsURL == "" {
		return
	}
	e.mu.Lock()
	due := !e.fetching && time.Until(vkturn.Expiry(e.creds)) < turnRefreshBefore && time.Since(e.lastFetch) >= turnFetchEvery
	if due {
		e.fetching, e.lastFetch = true, time.Now()
	}
	e.mu.Unlock()
	if !due {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		creds, err := fetchTURNCreds(ctx, s)
		if err == nil {
			e.offer(creds)
		}
		e.mu.Lock()
		e.fetching = false
		e.mu.Unlock()
	}()
}

// fetchTURNCreds asks the path's creds URL for fresh creds, over the path
// itself: where only VK's relays pass, nothing else reaches the provider.
func fetchTURNCreds(ctx context.Context, s PathSpec) ([]vkturn.Creds, error) {
	u, err := url.Parse(s.TURN.CredsURL)
	if err != nil {
		return nil, err
	}
	port := 443
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil {
			return nil, err
		}
	}
	w, err := Build(s)
	if err != nil {
		return nil, err
	}
	defer w.Close()
	sess, err := w.Dial(ctx)
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	rc := newRunConn(ctx, sess, Target{Host: u.Hostname(), Port: port})
	defer rc.Close()
	tc := tls.Client(rc, &tls.Config{ServerName: u.Hostname()})
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Connection", "close")
	if err := req.Write(tc); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vkturn: creds url answered %d", resp.StatusCode)
	}
	var body struct {
		Creds []vkturn.Creds `json:"creds"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body); err != nil {
		return nil, err
	}
	if len(body.Creds) == 0 {
		return nil, errors.New("vkturn: creds url gave none")
	}
	return body.Creds, nil
}

// runConn is a net.Conn over one Session.Run: the core's own request riding
// a path like an app's flow.
type runConn struct {
	ctx    context.Context
	cancel context.CancelFunc
	up     chan []byte
	pr     *io.PipeReader
}

type quietMeter struct{}

func (quietMeter) Up([]byte)   {}
func (quietMeter) Down([]byte) {}

func newRunConn(ctx context.Context, sess Session, target Target) *runConn {
	ctx, cancel := context.WithCancel(ctx)
	pr, pw := io.Pipe()
	c := &runConn{ctx: ctx, cancel: cancel, up: make(chan []byte, 16), pr: pr}
	go func() {
		_, err := sess.Run(ctx, target, nil, c.up, pw, quietMeter{})
		if err == nil {
			err = io.EOF
		}
		pw.CloseWithError(err)
	}()
	return c
}

func (c *runConn) Read(p []byte) (int, error) { return c.pr.Read(p) }

func (c *runConn) Write(p []byte) (int, error) {
	select {
	case c.up <- append([]byte(nil), p...):
		return len(p), nil
	case <-c.ctx.Done():
		return 0, net.ErrClosed
	}
}

func (c *runConn) Close() error {
	c.cancel()
	return c.pr.Close()
}

func (c *runConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *runConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *runConn) SetDeadline(time.Time) error      { return nil }
func (c *runConn) SetReadDeadline(time.Time) error  { return nil }
func (c *runConn) SetWriteDeadline(time.Time) error { return nil }
