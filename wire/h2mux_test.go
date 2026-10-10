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

// freezeDialer is h2EchoDialer behind a relay that freeze turns into a black
// hole for the connections made so far, the way a NAT that forgot a
// connection, or a network the phone left, kills it in silence: bytes go out
// and nothing comes back, and nothing closes. Connections dialed later work.
type freezeDialer struct {
	h2EchoDialer
	mu     sync.Mutex
	frozen []*atomic.Bool
}

func (d *freezeDialer) dial(ctx context.Context) (net.Conn, error) {
	srv, err := d.h2EchoDialer.dial(ctx)
	if err != nil {
		return nil, err
	}
	c, mid := net.Pipe()
	dead := &atomic.Bool{}
	d.mu.Lock()
	d.frozen = append(d.frozen, dead)
	d.mu.Unlock()
	relay := func(dst, src net.Conn) {
		buf := make([]byte, 4096)
		for {
			n, err := src.Read(buf)
			if err != nil {
				dst.Close()
				return
			}
			if !dead.Load() {
				dst.Write(buf[:n])
			}
		}
	}
	go relay(srv, mid)
	go relay(mid, srv)
	return c, nil
}

func (d *freezeDialer) freeze() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, f := range d.frozen {
		f.Store(true)
	}
}

// answers reports whether msg comes back on s within wait.
func answers(s net.Conn, msg string, wait time.Duration) bool {
	if _, err := s.Write([]byte(msg)); err != nil {
		return false
	}
	got := make(chan bool, 1)
	go func() {
		b := make([]byte, len(msg))
		_, err := io.ReadFull(s, b)
		got <- err == nil && string(b) == msg
	}()
	select {
	case ok := <-got:
		return ok
	case <-time.After(wait):
		return false
	}
}

// After refresh, a connection that died in silence takes no new stream: the
// next one dials afresh and works, and the stream stuck on the dead one is
// released once the PING goes unanswered.
func TestH2MuxRefreshLeavesADeadConnection(t *testing.T) {
	defer func(d time.Duration) { retirePingTimeout = d }(retirePingTimeout)
	retirePingTimeout = 300 * time.Millisecond
	d := &freezeDialer{}
	m := newH2Mux(d.dial, 0, 0)
	defer m.Close()

	a := openOrFail(t, m)
	echo(t, a, "first")
	a.Close()
	d.freeze()
	stuck := openOrFail(t, m)
	if answers(stuck, "lost", 300*time.Millisecond) {
		t.Fatal("setup: the frozen connection answered")
	}
	if got := d.count(); got != 1 {
		t.Fatalf("setup: the stuck stream should have ridden the dead connection, %d dials", got)
	}

	m.refresh(time.Now())
	b := openOrFail(t, m)
	if !answers(b, "fresh", 2*time.Second) {
		t.Fatal("the stream after refresh did not get through")
	}
	b.Close()
	if got := d.count(); got != 2 {
		t.Fatalf("expected a fresh dial after refresh, got %d dials", got)
	}

	released := make(chan struct{})
	go func() {
		stuck.Read(make([]byte, 1))
		close(released)
	}()
	select {
	case <-released:
	case <-time.After(3 * time.Second):
		t.Fatal("the stream on the dead connection still hangs")
	}
	stuck.Close()
}

// refresh never cuts a live connection under its streams: they finish there
// while new streams ride a fresh connection.
func TestH2MuxRefreshKeepsLiveStreams(t *testing.T) {
	defer func(d time.Duration) { retirePingTimeout = d }(retirePingTimeout)
	retirePingTimeout = 300 * time.Millisecond
	d := &h2EchoDialer{}
	m := newH2Mux(d.dial, 0, 0)
	defer m.Close()

	a := openOrFail(t, m)
	echo(t, a, "before")
	m.refresh(time.Now())
	b := openOrFail(t, m)
	echo(t, b, "new")
	time.Sleep(3 * retirePingTimeout)
	echo(t, a, "still-here")
	a.Close()
	b.Close()
	if got := d.count(); got != 2 {
		t.Fatalf("expected 2 dials, got %d", got)
	}
}

// A connection left with no streams for the Transport's IdleConnTimeout is
// closed, so the next stream dials afresh (outerTransport sets h2IdleClose).
func TestH2MuxIdleConnectionIsClosed(t *testing.T) {
	d := &h2EchoDialer{}
	m := newH2Mux(d.dial, 0, 0)
	m.tr.IdleConnTimeout = 100 * time.Millisecond
	defer m.Close()

	a := openOrFail(t, m)
	echo(t, a, "first")
	a.Close()
	time.Sleep(400 * time.Millisecond)
	b := openOrFail(t, m)
	echo(t, b, "second")
	b.Close()
	if got := d.count(); got != 2 {
		t.Fatalf("expected the idle connection closed and a fresh dial, got %d dials", got)
	}
}

// A refresh for flows that began before the current connection was made leaves
// it alone: several flows that met a dead connection at once retire it once,
// not each fresh one dialed after it.
func TestH2MuxRefreshSparesANewerConnection(t *testing.T) {
	d := &h2EchoDialer{}
	m := newH2Mux(d.dial, 0, 0)
	defer m.Close()

	began := time.Now()
	time.Sleep(10 * time.Millisecond)
	a := openOrFail(t, m)
	echo(t, a, "made after the flow began")
	m.refresh(began)
	b := openOrFail(t, m)
	echo(t, b, "same connection")
	a.Close()
	b.Close()
	if got := d.count(); got != 1 {
		t.Fatalf("a connection newer than the flow was left behind: %d dials", got)
	}
}

// needsDial is what the handshake governor paces by: a stream that rides the
// connection already up runs no handshake and must not wait for a slot.
func TestH2MuxNeedsDialOnlyWithoutAUsableConnection(t *testing.T) {
	d := &h2EchoDialer{}
	m := newH2Mux(d.dial, 0, 0)
	defer m.Close()
	if !m.needsDial() {
		t.Fatal("no connection yet, but no dial needed")
	}
	a := openOrFail(t, m)
	echo(t, a, "up")
	if m.needsDial() {
		t.Fatal("a stream on the live connection was counted as a handshake")
	}
	m.refresh(time.Now().Add(time.Millisecond))
	if !m.needsDial() {
		t.Fatal("after refresh the next stream dials, but no dial needed")
	}
	a.Close()
}

// tcp and ws connect per flow: every dial is a handshake.
func TestPerFlowTransportsAlwaysHandshake(t *testing.T) {
	for _, n := range []string{"tcp", "ws"} {
		if !newOuterTransport(PathSpec{Network: n}).needsHandshake() {
			t.Fatalf("%s: a per-flow connection was not counted as a handshake", n)
		}
	}
}
