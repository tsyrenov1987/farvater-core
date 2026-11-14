package wire

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/tsyrenov1987/farvater-core/kilvater"
)

// kilLab is a kilvater server on in-process connections the test can cut.
type kilLab struct {
	t   *testing.T
	srv *kilvater.Server

	mu    sync.Mutex
	conns []net.Conn
	down  bool // refuse new connections
}

func (l *kilLab) dial(ctx context.Context) (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.down {
		return nil, errors.New("lab: path is down")
	}
	c, s := net.Pipe()
	l.conns = append(l.conns, c, s)
	go (&http2.Server{}).ServeConn(s, &http2.ServeConnOpts{Handler: l.srv})
	return c, nil
}

// cut resets every connection made so far, as a path that kills them would.
func (l *kilLab) cut() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.conns {
		c.Close()
	}
	l.conns = nil
}

func (l *kilLab) setDown(v bool) {
	l.mu.Lock()
	l.down = v
	l.mu.Unlock()
}

func newKilLab(t *testing.T, grace time.Duration) (*kilLab, PathSpec) {
	var master kilvater.Key
	rand.Read(master[:])
	id := kilvater.KeyIDFor(master, []byte("resume"))
	k := kilvater.DeriveKey(master, id)
	spec := kilTestSpec(hex.EncodeToString(k[:]))
	spec.KeyID = id.String()
	l := &kilLab{t: t, srv: &kilvater.Server{
		Verifier: kilvater.NewVerifierConfig(kilvater.VerifierConfig{Master: &master}),
		Decoy:    http.HandlerFunc(kilDecoy), AllowPrivate: true, ResumeGrace: grace}}
	t.Cleanup(l.cut)
	return l, spec
}

// kilFlow is one flow to the echo target, driven by the test.
type kilFlow struct {
	up    chan []byte
	pr    *io.PipeReader
	ended chan error
	out   Outcome
}

func startKilFlow(t *testing.T, w Wire) *kilFlow {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	sess, err := w.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port := echoTCP(t)
	f := &kilFlow{up: make(chan []byte, 1), ended: make(chan error, 1)}
	pr, pw := io.Pipe()
	f.pr = pr
	go func() {
		o, err := sess.Run(ctx, Target{Host: "127.0.0.1", Port: port}, []byte("hello "), f.up, pw, nopMeter{})
		f.out = o
		pw.CloseWithError(err)
		f.ended <- err
	}()
	return f
}

func (f *kilFlow) expect(t *testing.T, want string) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(f.pr, got); err != nil || string(got) != want {
		t.Fatalf("echo %q (%v), want %q", got, err, want)
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// A flow whose connection is reset goes on over a new one: what was sent
// before, across and after the cut all comes back, once and in order.
func TestKilvaterResumeAfterReset(t *testing.T) {
	lab, spec := newKilLab(t, 5*time.Second)
	w, err := newKilWire(spec, lab.dial)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	f := startKilFlow(t, w)
	f.expect(t, "hello ")
	before, _ := KilvaterResumeCounts()

	lab.cut()
	f.up <- []byte("after the cut")
	f.expect(t, "after the cut")
	if now, _ := KilvaterResumeCounts(); now == before {
		t.Fatal("the flow went on, but no resumption was counted")
	}
	if rs := lab.srv.ResumeStats(); rs.Resumed == 0 {
		t.Fatalf("server counted no resumed stream: %+v", rs)
	}

	lab.cut()
	lab.cut()
	f.up <- []byte(" and again")
	f.expect(t, " and again")

	close(f.up)
	go io.Copy(io.Discard, f.pr)
	select {
	case <-f.ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the flow did not end")
	}
	// The client said it was done: the server keeps nothing for it.
	waitFor(t, "the server to drop the session", func() bool {
		rs := lab.srv.ResumeStats()
		return rs.Kept == 0 && rs.HeldBytes == 0
	})
}

// A transfer larger than both windows survives cuts in the middle of it with
// every byte in place.
func TestKilvaterResumeBulkIntegrity(t *testing.T) {
	lab, spec := newKilLab(t, 5*time.Second)
	w, err := newKilWire(spec, lab.dial)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	f := startKilFlow(t, w)
	f.expect(t, "hello ")

	const total = 6 << 20
	want := make([]byte, total)
	rand.Read(want)
	go func() {
		for off := 0; off < total; off += 16 << 10 {
			f.up <- want[off : off+16<<10]
		}
	}()
	got := make([]byte, total)
	cuts := map[int]bool{1 << 20: true, 3 << 20: true, 5 << 20: true}
	for n := 0; n < total; {
		m, err := f.pr.Read(got[n:])
		if err != nil {
			t.Fatalf("read failed at %d of %d: %v", n, total, err)
		}
		for at := range cuts {
			if n < at && n+m >= at {
				delete(cuts, at)
				lab.cut()
			}
		}
		n += m
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the bytes that came back are not the bytes sent")
	}
	if rs := lab.srv.ResumeStats(); rs.Resumed < 3 {
		t.Fatalf("server resumed %d streams, want at least 3", rs.Resumed)
	}
}

// A flow that cannot return on its own path continues on another wire with
// the same key: the key is bound to the node, so that wire leads to it.
func TestKilvaterResumeOnSiblingPath(t *testing.T) {
	lab, spec := newKilLab(t, 5*time.Second)
	a, err := newKilWire(spec, lab.dial)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	other := &kilLab{t: t, srv: lab.srv}
	t.Cleanup(other.cut)
	specB := spec
	specB.ID = "kv-b"
	b, err := newKilWire(specB, other.dial)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	f := startKilFlow(t, a)
	f.expect(t, "hello ")
	lab.setDown(true) // the first path is blocked for good
	lab.cut()
	f.up <- []byte("by the other path")
	f.expect(t, "by the other path")
}

// Against a server that does not keep sessions the flow runs as it always
// did, ends with its stream, and the wire stops asking.
func TestKilvaterResumeOldServer(t *testing.T) {
	lab, spec := newKilLab(t, 0)
	w, err := newKilWire(spec, lab.dial)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	f := startKilFlow(t, w)
	f.expect(t, "hello ")
	if w.resumeWanted() {
		t.Fatal("the server sent DATA with no ACK before it, and the wire still asks for sessions")
	}
	lab.cut()
	select {
	case err := <-f.ended:
		if err == nil {
			t.Fatal("the flow ended without an error after its connection was cut")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the flow did not end with its stream")
	}
	// The next flow sends a plain OPEN and works.
	f2 := startKilFlow(t, w)
	f2.expect(t, "hello ")
}

// The client must not wait forever on a server that never confirms: an
// upload of more than a window to a server that stays silent goes through.
func TestKilvaterResumeUploadToSilentOldServer(t *testing.T) {
	defer func(d time.Duration) { kilResumeProbe = d }(kilResumeProbe)
	kilResumeProbe = 50 * time.Millisecond

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const total = 3 << 20
	sunk := make(chan int, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		n, _ := io.CopyN(io.Discard, c, total+6)
		sunk <- int(n)
	}()

	lab, spec := newKilLab(t, 0)
	w, err := newKilWire(spec, lab.dial)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sess, err := w.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	up := make(chan []byte)
	go sess.Run(ctx, Target{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port}, []byte("hello "), up, io.Discard, nopMeter{})
	chunk := make([]byte, 16<<10)
	go func() {
		for n := 0; n < total; n += len(chunk) {
			select {
			case up <- chunk:
			case <-ctx.Done():
				return
			}
		}
	}()
	select {
	case n := <-sunk:
		if n != total+6 {
			t.Fatalf("the target got %d bytes, want %d", n, total+6)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the upload stalled: the client waits for a confirmation that will never come")
	}
}
