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

// capEdge is a CDN edge that cuts a connection once it has carried cap bytes,
// as CDN Timeweb's does at 175 to 201 MiB (19.11).
type capEdge struct {
	h    http.Handler
	cap  int64
	cuts atomic.Int64
	mu   sync.Mutex
	all  []net.Conn
}

type capConn struct {
	net.Conn
	e *capEdge
	n *atomic.Int64
}

func (c capConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.n.Add(int64(n)) > c.e.cap {
		c.e.cuts.Add(1)
		c.Conn.Close()
	}
	return n, err
}

func (c capConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if c.n.Add(int64(n)) > c.e.cap {
		c.e.cuts.Add(1)
		c.Conn.Close()
	}
	return n, err
}

func (e *capEdge) dial(ctx context.Context) (net.Conn, error) {
	c, s := net.Pipe()
	e.mu.Lock()
	e.all = append(e.all, c, s)
	e.mu.Unlock()
	go (&http2.Server{}).ServeConn(s, &http2.ServeConnOpts{Handler: e.h})
	return capConn{Conn: c, e: e, n: new(atomic.Int64)}, nil
}

func (e *capEdge) close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, c := range e.all {
		c.Close()
	}
}

// A split flow that carries more than the edge lets one connection carry
// moves to fresh connections before the edge cuts: no cut, no lost byte.
func TestKilvaterSplitRollsBeforeEdgeCut(t *testing.T) {
	old := kilSplitRollBytes.Load()
	kilSplitRollBytes.Store(3 << 20)
	defer kilSplitRollBytes.Store(old)

	lab, spec := newKilLab(t, 5*time.Second)
	spec.Mode = "split-post"
	edge := &capEdge{h: lab.srv, cap: 6 << 20}
	defer edge.close()
	w, err := newKilWire(spec, edge.dial)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	w.mux.maxBytes = 2 << 20 // 1.4 to 2.6 MiB with the spread, under the roll
	rolled := KilvaterRollCount()

	f := startKilFlow(t, w)
	f.expect(t, "hello ")
	const total = 8 << 20 // echoed: 16 MiB through, plus the uplink
	want := make([]byte, total)
	rand.Read(want)
	go func() {
		for off := 0; off < total; off += 16 << 10 {
			f.up <- want[off : off+16<<10]
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
		i := 0
		for i < total && got[i] == want[i] {
			i++
		}
		j := bytes.Index(want, got[i:i+64])
		t.Fatalf("the bytes that came back are not the bytes sent: first difference at %d, what came there is from %d", i, j)
	}
	if c := edge.cuts.Load(); c != 0 {
		t.Fatalf("the edge cut %d times: the flow did not move off in time", c)
	}
	if r := KilvaterRollCount() - rolled; r < 2 {
		t.Fatalf("the flow moved %d times, want at least 2", r)
	}
}
