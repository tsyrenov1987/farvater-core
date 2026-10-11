package wire

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/tsyrenov1987/farvater-core/kilvater"
)

func kilTestKey(t *testing.T) (kilvater.Key, string) {
	t.Helper()
	b := make([]byte, 32)
	rand.Read(b)
	h := hex.EncodeToString(b)
	k, err := kilvater.ParseKey(h)
	if err != nil {
		t.Fatal(err)
	}
	return k, h
}

func kilTestSpec(hexKey string) PathSpec {
	return PathSpec{ID: "kv", Kind: KindKilvater, Host: "kv.test", Port: 443, SNI: "kv.test",
		Fingerprint: "chrome", Key: hexKey, Path: "/connect"}
}

// kilDecoy answers like the file server kilvaterd puts in front: a page at
// "/" with two assets, 404 elsewhere.
func kilDecoy(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/", "/s.css", "/a.js":
		ctype, body := h2fpContent(r.URL.Path)
		w.Header().Set("Content-Type", ctype)
		w.Write(body)
	default:
		http.NotFound(w, r)
	}
}

func kilServerFor(key kilvater.Key) *kilvater.Server {
	return &kilvater.Server{Verifier: kilvater.NewVerifier([]kilvater.Key{key}),
		Decoy: http.HandlerFunc(kilDecoy), AllowPrivate: true}
}

// kilServerDial serves kilvater on in-process HTTP/2 connections. There is
// no TLS here: these tests look at what rides inside it.
func kilServerDial(t *testing.T, key kilvater.Key) func(context.Context) (net.Conn, error) {
	srv := kilServerFor(key)
	return func(ctx context.Context) (net.Conn, error) {
		c, s := net.Pipe()
		t.Cleanup(func() { s.Close() })
		go (&http2.Server{}).ServeConn(s, &http2.ServeConnOpts{Handler: srv})
		return c, nil
	}
}

func TestKilvaterFlow(t *testing.T) {
	key, hexKey := kilTestKey(t)
	w, err := newKilWire(kilTestSpec(hexKey), kilServerDial(t, key))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	flowEchoOver(t, w)
}

// A link carrying a key id makes the client send v2 tags; a server that holds
// the master derives the key by id and the tunnel runs end to end.
func TestKilvaterV2Flow(t *testing.T) {
	var master kilvater.Key
	rand.Read(master[:])
	id := kilvater.KeyIDFor(master, []byte("e2e"))
	k := kilvater.DeriveKey(master, id)

	spec := kilTestSpec(hex.EncodeToString(k[:]))
	spec.KeyID = id.String()

	srv := &kilvater.Server{
		Verifier: kilvater.NewVerifierConfig(kilvater.VerifierConfig{Master: &master}),
		Decoy:    http.HandlerFunc(kilDecoy), AllowPrivate: true}
	dial := func(ctx context.Context) (net.Conn, error) {
		c, s := net.Pipe()
		t.Cleanup(func() { s.Close() })
		go (&http2.Server{}).ServeConn(s, &http2.ServeConnOpts{Handler: srv})
		return c, nil
	}

	w, err := newKilWire(spec, dial)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	flowEchoOver(t, w)
}

// UDP rides kilvater end to end: DialPacket opens a stream, each datagram
// crosses as its own frame to a connected socket on the server, and the echo's
// answers come back whole. A DNS query is exactly this — a datagram to :53 —
// so DNS rides the same path.
func TestKilvaterUDPFlow(t *testing.T) {
	key, hexKey := kilTestKey(t)
	w, err := newKilWire(kilTestSpec(hexKey), kilServerDial(t, key))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ps, err := w.DialPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()

	echo := udpEcho(t)
	target := Target{Host: "127.0.0.1", Port: echo.Port}
	for i := 0; i < 3; i++ {
		msg := fmt.Sprintf("dg%d", i)
		if err := ps.WritePacket([]byte(msg), target); err != nil {
			t.Fatalf("datagram %d: write: %v", i, err)
		}
		got, errc := make(chan []byte, 1), make(chan error, 1)
		go func() {
			p, _, err := ps.ReadPacket()
			if err != nil {
				errc <- err
				return
			}
			got <- p
		}()
		want := fmt.Sprintf("%d:%s", echo.Port, msg)
		select {
		case p := <-got:
			if string(p) != want {
				t.Fatalf("datagram %d: got %q, want %q", i, p, want)
			}
		case err := <-errc:
			t.Fatalf("datagram %d: read: %v", i, err)
		case <-time.After(5 * time.Second):
			t.Fatalf("datagram %d: no answer", i)
		}
	}
}

// A phone whose clock is off by more than the tag window still connects: the
// tag takes the server's time from the page fetched first.
func TestKilvaterSkewedClockConnects(t *testing.T) {
	for _, skew := range []time.Duration{10 * time.Minute, -10 * time.Minute} {
		key, hexKey := kilTestKey(t)
		w, err := newKilWire(kilTestSpec(hexKey), kilServerDial(t, key))
		if err != nil {
			t.Fatal(err)
		}
		w.now = func() time.Time { return time.Now().Add(skew) }
		flowEchoOver(t, w)
		w.Close()
	}
}

// tcpPair is a connected loopback TCP pair.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); s.Close() })
	return c, s
}

func loadH2FP(t *testing.T, path string) h2fpCapture {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c h2fpCapture
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func h2fpHeader(f h2fpFrame, name string) (string, bool) {
	for _, h := range f.Headers {
		if h[0] == name {
			return h[1], true
		}
	}
	return "", false
}

func h2fpNames(f h2fpFrame, pseudo bool) []string {
	var n []string
	for _, h := range f.Headers {
		if strings.HasPrefix(h[0], ":") == pseudo {
			n = append(n, h[0])
		}
	}
	return n
}

// h2fpUrgency is the u= of a request's priority header, "3" without one
// (RFC 9218).
func h2fpUrgency(f h2fpFrame) string {
	v, _ := h2fpHeader(f, "priority")
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); strings.HasPrefix(p, "u=") {
			return p[2:]
		}
	}
	return "3"
}

func h2fpFind(c h2fpCapture, ok func(h2fpFrame) bool) (h2fpFrame, bool) {
	for _, f := range c.Frames {
		if ok(f) {
			return f, true
		}
	}
	return h2fpFrame{}, false
}

// TestKilvaterH2MatchesChrome holds what our client sends on a new connection
// to the browser recorded in testdata/h2fp: the SETTINGS and the connection
// window; on every request the pseudo-header order and the priority Chrome
// gives that urgency; the order of the other headers on the page request and
// on a streamed fetch POST, which the tunnel request is; and the page request
// coming first.
func TestKilvaterH2MatchesChrome(t *testing.T) {
	ref := loadH2FP(t, "testdata/h2fp/chrome-154.json")
	_, hexKey := kilTestKey(t)
	got := make(chan h2fpCapture, 1)
	dial := func(ctx context.Context) (net.Conn, error) {
		c, s := tcpPair(t) // buffered: the capture server writes from the reading goroutine
		go func() {
			var cap h2fpCapture
			srv := &h2fpServer{early: true, page: h2fpContent, done: "/connect", linger: 300 * time.Millisecond}
			if err := srv.serve(s, time.Now(), &cap); err != nil {
				t.Logf("capture: %v", err)
			}
			s.Close()
			got <- cap
		}()
		return c, nil
	}
	w, err := newKilWire(kilTestSpec(hexKey), dial)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := w.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	var c h2fpCapture
	select {
	case c = <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("no capture")
	}

	isType := func(typ string) func(h2fpFrame) bool { return func(f h2fpFrame) bool { return f.Type == typ } }
	settings := func(f h2fpFrame) bool { return f.Type == "SETTINGS" && !f.Ack }
	connWindow := func(f h2fpFrame) bool { return f.Type == "WINDOW_UPDATE" && f.Stream == 0 }
	rs, _ := h2fpFind(ref, settings)
	gs, _ := h2fpFind(c, settings)
	if !reflect.DeepEqual(gs.Settings, rs.Settings) {
		t.Errorf("SETTINGS %v, want %v", gs.Settings, rs.Settings)
	}
	rw, _ := h2fpFind(ref, connWindow)
	gw, _ := h2fpFind(c, connWindow)
	if gw.Increment != rw.Increment {
		t.Errorf("connection WINDOW_UPDATE %d, want %d", gw.Increment, rw.Increment)
	}
	if _, ok := h2fpFind(ref, isType("PRIORITY")); !ok {
		if f, ok := h2fpFind(c, isType("PRIORITY")); ok {
			t.Errorf("PRIORITY frame on stream %d; the browser sends none", f.Stream)
		}
	}

	refHeaders, _ := h2fpFind(ref, isType("HEADERS"))
	refPseudo := h2fpNames(refHeaders, true)
	weights := map[string]int{}
	for _, f := range ref.Frames {
		if f.Type == "HEADERS" && f.Priority != nil {
			weights[h2fpUrgency(f)] = f.Priority.Weight
		}
	}
	var heads []h2fpFrame
	for _, f := range c.Frames {
		if f.Type == "HEADERS" {
			heads = append(heads, f)
		}
	}
	if len(heads) == 0 {
		t.Fatal("no HEADERS captured")
	}
	for _, f := range heads {
		path, _ := h2fpHeader(f, ":path")
		if p := h2fpNames(f, true); !reflect.DeepEqual(p, refPseudo) {
			t.Errorf("%s: pseudo-headers %v, want %v", path, p, refPseudo)
		}
		u := h2fpUrgency(f)
		want, ok := weights[u]
		switch {
		case !ok:
			t.Errorf("%s: urgency %s, which the reference never uses", path, u)
		case f.Priority == nil:
			t.Errorf("%s: no priority on HEADERS; the browser sets it on every request", path)
		case !f.Priority.Exclusive || f.Priority.Weight != want:
			t.Errorf("%s: priority %+v, want exclusive weight %d", path, *f.Priority, want)
		}
	}

	navigate := func(f h2fpFrame) bool {
		m, _ := h2fpHeader(f, "sec-fetch-mode")
		return f.Type == "HEADERS" && m == "navigate"
	}
	streamedPost := func(f h2fpFrame) bool {
		m, _ := h2fpHeader(f, ":method")
		_, sized := h2fpHeader(f, "content-length")
		return f.Type == "HEADERS" && m == "POST" && !sized
	}
	for _, k := range []struct {
		name string
		ok   func(h2fpFrame) bool
	}{{"page request", navigate}, {"streamed POST", streamedPost}} {
		r, _ := h2fpFind(ref, k.ok)
		g, found := h2fpFind(c, k.ok)
		if !found {
			t.Errorf("%s: none sent", k.name)
			continue
		}
		if gn, rn := h2fpNames(g, false), h2fpNames(r, false); !reflect.DeepEqual(gn, rn) {
			t.Errorf("%s: headers\n %v\nwant\n %v", k.name, gn, rn)
		}
	}
	if !navigate(heads[0]) {
		p, _ := h2fpHeader(heads[0], ":path")
		t.Errorf("first request %s; a browser opens a connection with the page", p)
	}
}
