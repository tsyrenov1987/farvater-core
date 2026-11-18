package wire

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// Well into a connection's age the next one is made in the background, and
// the stream that rotates takes it without dialing.
func TestH2MuxMakesNextConnectionAhead(t *testing.T) {
	d := &h2EchoDialer{}
	m := newH2Mux(d.dial, 0, 0)
	m.maxAge, m.ahead = 400*time.Millisecond, 0.5
	defer m.Close()

	a := openOrFail(t, m)
	echo(t, a, "first")
	defer a.Close()
	if got := d.count(); got != 1 {
		t.Fatalf("setup: expected 1 dial, got %d", got)
	}
	time.Sleep(250 * time.Millisecond) // past half the age, short of it

	b := openOrFail(t, m) // still on connection 1; starts the next one
	echo(t, b, "second")
	b.Close()
	for i := 0; d.count() < 2; i++ {
		if i == 100 {
			t.Fatal("the next connection was not made ahead")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond) // connection 1 is past its age
	for i := 0; m.needsDial(); i++ {
		if i == 100 {
			t.Fatal("a connection is ready, but needsDial says the next stream handshakes")
		}
		time.Sleep(5 * time.Millisecond)
	}
	c := openOrFail(t, m)
	echo(t, c, "third")
	c.Close()
	if got := d.count(); got != 2 {
		t.Fatalf("the rotating stream dialed: %d dials, want 2", got)
	}
	echo(t, a, "still here") // the old connection drains under its stream
}

// With ahead off nothing is dialed before the rotation.
func TestH2MuxNoSpareByDefault(t *testing.T) {
	d := &h2EchoDialer{}
	m := newH2Mux(d.dial, 0, 0)
	m.maxAge = 200 * time.Millisecond
	defer m.Close()
	a := openOrFail(t, m)
	echo(t, a, "first")
	a.Close()
	time.Sleep(180 * time.Millisecond)
	b := openOrFail(t, m)
	echo(t, b, "second")
	b.Close()
	time.Sleep(50 * time.Millisecond)
	if got := d.count(); got > 2 {
		t.Fatalf("%d dials, want at most 2", got)
	}
}

// Each connection draws its own limits around the configured ones.
func TestSpreadDuration(t *testing.T) {
	if got := spreadDuration(time.Minute, 0); got != time.Minute {
		t.Fatalf("no spread: %v", got)
	}
	seen := map[time.Duration]bool{}
	for range 200 {
		got := spreadDuration(10*time.Minute, 0.3)
		if got < 7*time.Minute || got > 13*time.Minute {
			t.Fatalf("%v is outside 7..13 min", got)
		}
		seen[got] = true
	}
	if len(seen) < 100 {
		t.Fatalf("only %d distinct limits in 200 draws", len(seen))
	}
}

// The second connection revalidates the page and its assets instead of
// fetching them again, as a browser with the site in its cache does.
func TestKilvaterWarmRevalidates(t *testing.T) {
	type seen struct{ path, inm, ims string }
	var mu sync.Mutex
	var reqs []seen
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reqs = append(reqs, seen{r.URL.Path, r.Header.Get("If-None-Match"), r.Header.Get("If-Modified-Since")})
		mu.Unlock()
		switch r.URL.Path {
		case "/", "/s.css", "/a.js":
			etag := `"v1` + r.URL.Path + `"`
			w.Header().Set("ETag", etag)
			w.Header().Set("Last-Modified", "Mon, 02 Nov 2026 10:00:00 GMT")
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			ctype, body := h2fpContent(r.URL.Path)
			w.Header().Set("Content-Type", ctype)
			w.Write(body)
		default:
			http.NotFound(w, r)
		}
	})
	dial := func(ctx context.Context) (net.Conn, error) {
		c, s := net.Pipe()
		go (&http2.Server{}).ServeConn(s, &http2.ServeConnOpts{Handler: h})
		return c, nil
	}
	_, hexKey := kilTestKey(t)
	w, err := newKilWire(kilTestSpec(hexKey), dial)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	paths := func() map[string]seen {
		// The assets and the favicon may still be on their way.
		for i := 0; ; i++ {
			mu.Lock()
			n := len(reqs)
			out := map[string]seen{}
			for _, r := range reqs {
				out[r.path] = r
			}
			mu.Unlock()
			if n >= 4 || i == 200 {
				return out
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	for round := 1; round <= 2; round++ {
		mu.Lock()
		reqs = nil
		mu.Unlock()
		c, err := dial(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		cc, err := w.mux.tr.NewClientConn(c)
		if err != nil {
			t.Fatal(err)
		}
		w.warm(context.Background(), cc)
		got := paths()
		for _, p := range []string{"/", "/s.css", "/a.js"} {
			r, ok := got[p]
			if !ok {
				t.Fatalf("round %d: %s was not asked for (%v)", round, p, got)
			}
			if round == 1 && (r.inm != "" || r.ims != "") {
				t.Fatalf("round 1: %s was asked for conditionally: %+v", p, r)
			}
			if round == 2 && (r.inm != `"v1`+p+`"` || r.ims == "") {
				t.Fatalf("round 2: %s was not revalidated: %+v", p, r)
			}
		}
		// The answers are remembered after they are read, in the background.
		for i := 0; i < 200; i++ {
			w.cacheMu.Lock()
			n := len(w.cache)
			w.cacheMu.Unlock()
			if n >= 3 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		cc.Close()
	}
}

// The first connection waits for the page's headers, which give the server's
// clock; later ones, with the clock known, do not wait for the page at all,
// and none waits for the page's body.
func TestKilvaterWarmWaits(t *testing.T) {
	const slow = 300 * time.Millisecond
	var headerDelay, bodyDelay atomic.Int64
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		time.Sleep(time.Duration(headerDelay.Load()))
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		time.Sleep(time.Duration(bodyDelay.Load()))
		w.Write([]byte("<html></html>"))
	})
	dial := func(ctx context.Context) (net.Conn, error) {
		c, s := net.Pipe()
		go (&http2.Server{}).ServeConn(s, &http2.ServeConnOpts{Handler: h})
		return c, nil
	}
	_, hexKey := kilTestKey(t)
	w, err := newKilWire(kilTestSpec(hexKey), dial)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	warm := func() time.Duration {
		c, _ := dial(context.Background())
		cc, err := w.mux.tr.NewClientConn(c)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cc.Close() })
		start := time.Now()
		w.warm(context.Background(), cc)
		return time.Since(start)
	}

	headerDelay.Store(int64(slow))
	bodyDelay.Store(int64(slow))
	if d := warm(); d < slow || d >= 2*slow {
		t.Fatalf("first connection warmed in %v: want the page's headers (%v) and not its body", d, slow)
	}
	if !w.clocked.Load() {
		t.Fatal("the page's Date was not taken")
	}
	if d := warm(); d >= slow/2 {
		t.Fatalf("second connection warmed in %v: want no wait for the page", d)
	}
}
