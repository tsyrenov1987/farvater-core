package wire

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// h2EchoDialer hands the mux one end of an in-process HTTP/2 connection whose
// server echoes each request body back as the response body, and counts how
// many connections were dialed. killLast drops the newest server side, the way
// a node that goes away would.
type h2EchoDialer struct {
	dials int32
	mu    sync.Mutex
	srv   []net.Conn
}

func (d *h2EchoDialer) dial(ctx context.Context) (net.Conn, error) {
	atomic.AddInt32(&d.dials, 1)
	c, s := net.Pipe()
	d.mu.Lock()
	d.srv = append(d.srv, s)
	d.mu.Unlock()
	go (&http2.Server{}).ServeConn(s, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			buf := make([]byte, 4096)
			for {
				n, err := r.Body.Read(buf)
				if n > 0 {
					w.Write(buf[:n])
					if f, ok := w.(http.Flusher); ok {
						f.Flush()
					}
				}
				if err != nil {
					return
				}
			}
		}),
	})
	return c, nil
}

func (d *h2EchoDialer) killLast() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.srv) > 0 {
		d.srv[len(d.srv)-1].Close()
	}
}

func (d *h2EchoDialer) count() int32 { return atomic.LoadInt32(&d.dials) }

// echo writes msg to the stream and reads the same number of bytes back,
// failing the test if the round trip does not match.
func echo(t *testing.T, s net.Conn, msg string) {
	t.Helper()
	if _, err := s.Write([]byte(msg)); err != nil {
		t.Fatalf("write %q: %v", msg, err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(s, got); err != nil {
		t.Fatalf("read back %q: %v", msg, err)
	}
	if string(got) != msg {
		t.Fatalf("echo mismatch: wrote %q, read %q", msg, string(got))
	}
}

func openOrFail(t *testing.T, m *h2Mux) net.Conn {
	t.Helper()
	s, err := m.openStream(context.Background(), http.MethodPost, "https://x/t", http.Header{})
	if err != nil {
		t.Fatalf("openStream: %v", err)
	}
	return s
}

// TestH2MuxReusesOneConnection: many concurrent streams ride one dial.
func TestH2MuxReusesOneConnection(t *testing.T) {
	d := &h2EchoDialer{}
	m := newH2Mux(d.dial, 0, 0)
	defer m.Close()

	streams := []net.Conn{openOrFail(t, m), openOrFail(t, m), openOrFail(t, m)}
	for i, s := range streams {
		echo(t, s, "hello")
		_ = i
	}
	for _, s := range streams {
		s.Close()
	}
	if got := d.count(); got != 1 {
		t.Fatalf("expected 1 dial for 3 streams, got %d", got)
	}
}

// TestH2MuxStreamCloseIsISolated: closing one stream leaves the connection and
// the other streams working — no new dial.
func TestH2MuxStreamCloseIsolated(t *testing.T) {
	d := &h2EchoDialer{}
	m := newH2Mux(d.dial, 0, 0)
	defer m.Close()

	a := openOrFail(t, m)
	b := openOrFail(t, m)
	echo(t, a, "aaa")
	echo(t, b, "bbb")

	a.Close() // reset stream A only

	echo(t, b, "still-here") // B must keep working on the same connection
	b.Close()

	if got := d.count(); got != 1 {
		t.Fatalf("closing one stream must not redial: got %d dials", got)
	}
}

// TestH2MuxFailsOverWhenConnectionDies: once the server drops the connection,
// the next stream dials a fresh one and works.
func TestH2MuxFailsOverWhenConnectionDies(t *testing.T) {
	d := &h2EchoDialer{}
	m := newH2Mux(d.dial, 0, 0)
	defer m.Close()

	a := openOrFail(t, m)
	echo(t, a, "first")
	a.Close()
	if got := d.count(); got != 1 {
		t.Fatalf("setup: expected 1 dial, got %d", got)
	}

	d.killLast()                       // the node goes away
	time.Sleep(200 * time.Millisecond) // let the client read loop notice the EOF

	b := openOrFail(t, m)
	echo(t, b, "second") // must ride a brand-new connection
	b.Close()

	if got := d.count(); got != 2 {
		t.Fatalf("expected a redial after the connection died, got %d dials", got)
	}
}

// TestH2MuxCloseBeforeReadIsRaceFree closes a stream before anything reads it,
// racing the in-flight RoundTrip that sets the stream's down side. Run with
// -race it guards the synchronization in Close (before it, Close read s.down
// without waiting for the goroutine that writes it).
func TestH2MuxCloseBeforeReadIsRaceFree(t *testing.T) {
	d := &h2EchoDialer{}
	m := newH2Mux(d.dial, 0, 0)
	defer m.Close()
	for i := 0; i < 50; i++ {
		s, err := m.openStream(context.Background(), http.MethodPost, "https://x/t", http.Header{})
		if err != nil {
			t.Fatalf("openStream: %v", err)
		}
		// Let RoundTrip reach its success branch, where it sets the stream's
		// down side, so Close races that write unless Close waits for it.
		time.Sleep(time.Millisecond)
		s.Close() // before any Read
	}
}
