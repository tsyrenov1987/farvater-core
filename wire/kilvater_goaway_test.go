package wire

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// goawayEdge is a CDN edge that ends each connection with a graceful GOAWAY
// once it has taken max requests, as CDN Timeweb's does after about 200
// (19.11): streams already taken finish, later ones are never processed.
type goawayEdge struct {
	h       http.Handler
	max     int64
	goaways atomic.Int64
	mu      sync.Mutex
	all     []net.Conn
}

func (e *goawayEdge) dial(ctx context.Context) (net.Conn, error) {
	c, s := net.Pipe()
	e.mu.Lock()
	e.all = append(e.all, c, s)
	e.mu.Unlock()
	hs := &http.Server{}
	h2 := &http2.Server{}
	http2.ConfigureServer(hs, h2)
	var n atomic.Int64
	var once sync.Once
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == e.max {
			once.Do(func() {
				e.goaways.Add(1)
				go hs.Shutdown(context.Background())
			})
		}
		e.h.ServeHTTP(w, r)
	})
	go h2.ServeConn(s, &http2.ServeConnOpts{Handler: h, BaseConfig: hs})
	return c, nil
}

func (e *goawayEdge) close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, c := range e.all {
		c.Close()
	}
}

// A split-post flow that sends more than an edge connection takes requests
// for goes on across its GOAWAYs: the pieces the edge never took go again on
// a new connection, the stream does not break, and every byte comes back.
func TestKilvaterSplitPostOutlivesEdgeGoaway(t *testing.T) {
	lab, spec := newKilLab(t, 5*time.Second)
	spec.Mode = "split-post"
	edge := &goawayEdge{h: lab.srv, max: 6}
	defer edge.close()
	w, err := newKilWire(spec, edge.dial)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	resumed, _ := KilvaterResumeCounts()

	f := startKilFlow(t, w)
	f.expect(t, "hello ")
	const total = 6 << 20
	want := make([]byte, total)
	rand.Read(want)
	go func() {
		for off := 0; off < total; off += 64 << 10 {
			f.up <- want[off : off+64<<10]
		}
	}()
	got := make([]byte, total)
	for n := 0; n < total; {
		m, err := f.pr.Read(got[n:])
		if err != nil {
			t.Fatalf("read failed at %d of %d: %v", n, total, err)
		}
		n += m
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the bytes that came back are not the bytes sent")
	}
	if g := edge.goaways.Load(); g < 3 {
		t.Fatalf("the edge sent %d GOAWAYs, want at least 3", g)
	}
	if r, _ := KilvaterResumeCounts(); r != resumed {
		t.Fatalf("the flow was resumed %d times: a GOAWAY broke the stream", r-resumed)
	}
}

// Split flows opened one after another across an edge's GOAWAYs all start:
// a downlink GET the edge never took goes again on a new connection rather
// than breaking the flow before its first byte.
func TestKilvaterSplitOpensAcrossEdgeGoaway(t *testing.T) {
	lab, spec := newKilLab(t, 5*time.Second)
	spec.Mode = "split-post"
	edge := &goawayEdge{h: lab.srv, max: 3}
	defer edge.close()
	w, err := newKilWire(spec, edge.dial)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	resumed, _ := KilvaterResumeCounts()
	for i := 0; i < 30; i++ {
		f := startKilFlow(t, w)
		f.expect(t, "hello ")
		f.pr.Close()
	}
	if g := edge.goaways.Load(); g < 10 {
		t.Fatalf("the edge sent %d GOAWAYs, want at least 10", g)
	}
	if r, _ := KilvaterResumeCounts(); r != resumed {
		t.Fatalf("flows were resumed %d times: a GOAWAY broke a flow", r-resumed)
	}
}
