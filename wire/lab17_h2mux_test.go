package wire

// Lab checks from the 17.11 audit pass: a node that shuts down gracefully
// (GOAWAY) mid-stream, and the heap that 200 concurrent flows cost.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func lab17EchoServer(t *testing.T) (*http.Server, string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	srv := &http.Server{Protocols: &p, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		buf := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
				w.(http.Flusher).Flush()
			}
			if err != nil {
				return
			}
		}
	})}
	go srv.Serve(ln)
	return srv, ln.Addr().String()
}

// A graceful server shutdown (GOAWAY) must leave the open stream running to
// its end, and the next stream must go out on a new connection, not fail.
func TestLab17H2MuxGoawayMidStream(t *testing.T) {
	srv, addr := lab17EchoServer(t)
	srv2, addr2 := lab17EchoServer(t) // the node back up behind the same name
	defer srv2.Close()
	var dials atomic.Int32
	m := newH2Mux(func(ctx context.Context) (net.Conn, error) {
		a := addr
		if dials.Add(1) > 1 {
			a = addr2
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", a)
	}, 0, 0)
	defer m.Close()
	a := openOrFail(t, m)
	echo(t, a, "before")
	shut := make(chan error, 1)
	go func() { shut <- srv.Shutdown(context.Background()) }()
	time.Sleep(300 * time.Millisecond) // let GOAWAY reach the client
	echo(t, a, "after-goaway")         // the old stream still works
	b, err := m.openStream(context.Background(), http.MethodPost, "https://x/t", http.Header{})
	if err != nil {
		t.Fatalf("open after GOAWAY: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.Write([]byte("x"))
		buf := make([]byte, 1)
		_, err := b.Read(buf)
		t.Logf("new stream after GOAWAY: dials=%d read err=%v", dials.Load(), err)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Errorf("new stream after GOAWAY hung (dials=%d)", dials.Load())
	}
	a.Close()
	b.Close()
	select {
	case <-shut:
	case <-time.After(3 * time.Second):
		t.Error("server Shutdown did not finish after the old stream closed")
	}
}

// 200 concurrent flows over one mux connection: heap in use with every flow
// open and 16 KiB echoed on each (client and server share this process, so the
// figure is an upper bound for the client).
func TestLab17H2Mux200Flows(t *testing.T) {
	srv, addr := lab17EchoServer(t)
	defer srv.Close()
	m := newH2Mux(func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}, 0, 0)
	defer m.Close()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	g0 := runtime.NumGoroutine()
	msg := strings.Repeat("z", 16<<10)
	var ss []net.Conn
	for i := 0; i < 200; i++ {
		s := openOrFail(t, m)
		echo(t, s, msg)
		ss = append(ss, s)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	g1 := runtime.NumGoroutine()
	t.Log(fmt.Sprintf("200 flows: heap in use +%.1f MiB, goroutines +%d (%.1f per flow, both sides)",
		float64(after.HeapInuse-before.HeapInuse)/(1<<20), g1-g0, float64(g1-g0)/200))
	for _, s := range ss {
		s.Close()
	}
	time.Sleep(500 * time.Millisecond)
	runtime.GC()
	runtime.GC() // sync.Pool victims survive one cycle
	var end runtime.MemStats
	runtime.ReadMemStats(&end)
	t.Logf("after close: heap in use %+.1f MiB vs start, goroutines %+d", (float64(end.HeapInuse)-float64(before.HeapInuse))/(1<<20), runtime.NumGoroutine()-g0)
}
