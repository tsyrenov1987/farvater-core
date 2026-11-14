package wire

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeGate is a gate on a clock the test moves, with no jitter.
func fakeGate(start time.Time) (*hsGate, *time.Time) {
	now := start
	g := newHSGate()
	g.now = func() time.Time { return now }
	g.jitter = func() time.Duration { return 0 }
	return g, &now
}

// reserveNow reserves with a context that is already past any wait: a slot
// later than now is refused rather than slept for, so the test never sleeps.
func reserveNow(g *hsGate, name, fp string) error {
	ctx, cancel := context.WithDeadline(context.Background(), g.now())
	defer cancel()
	_, err := g.reserve(ctx, name, fp)
	return err
}

// Two paced handshakes to a name in a minute, never closer than a second; the
// third is refused until the first leaves the window. Another name is not
// touched.
func TestHandshakeGateWindow(t *testing.T) {
	g, now := fakeGate(time.Unix(1_800_000_000, 0))
	if err := reserveNow(g, "a.example", "chrome"); err != nil {
		t.Fatalf("first: %v", err)
	}
	*now = now.Add(500 * time.Millisecond)
	if err := reserveNow(g, "a.example", "chrome"); !errors.Is(err, ErrHandshakePaced) {
		t.Fatalf("0.5 s after the first, with no time to wait: %v, want ErrHandshakePaced", err)
	}
	if g.held("a.example", "chrome") {
		t.Fatal("held with one handshake in the window: only the short gap is in the way")
	}
	*now = now.Add(500 * time.Millisecond)
	if err := reserveNow(g, "a.example", "chrome"); err != nil {
		t.Fatalf("1 s after the first: %v", err)
	}
	*now = now.Add(20 * time.Second)
	if err := reserveNow(g, "a.example", "chrome"); !errors.Is(err, ErrHandshakePaced) {
		t.Fatalf("third in a minute: %v, want ErrHandshakePaced", err)
	}
	if !g.held("a.example", "chrome") {
		t.Fatal("not held with the window full")
	}
	if g.held("b.example", "chrome") {
		t.Fatal("another name is held")
	}
	if err := reserveNow(g, "b.example", "chrome"); err != nil {
		t.Fatalf("another name: %v", err)
	}
	*now = now.Add(40 * time.Second) // 61 s after the first
	if g.held("a.example", "chrome") {
		t.Fatal("still held after the first left the window")
	}
	if err := reserveNow(g, "a.example", "chrome"); err != nil {
		t.Fatalf("after the first left the window: %v", err)
	}
}

// A slot whose ClientHello never went out (the TCP connect failed) is given
// back, and forgetting (a new network) empties the window.
func TestHandshakeGateCancelAndForget(t *testing.T) {
	g, now := fakeGate(time.Unix(1_800_000_000, 0))
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithDeadline(context.Background(), g.now())
		slot, err := g.reserve(ctx, "a.example", "")
		cancel()
		if err != nil {
			t.Fatalf("reserve %d after cancelled ones: %v", i, err)
		}
		g.cancel("a.example", slot)
	}
	for i := 0; i < 2; i++ {
		if err := reserveNow(g, "a.example", ""); err != nil {
			t.Fatal(err)
		}
		*now = now.Add(2 * time.Second)
	}
	if !g.held("a.example", "") {
		t.Fatal("setup: the window should be full")
	}
	g.forget()
	if g.held("a.example", "") || reserveNow(g, "a.example", "") != nil {
		t.Fatal("held after forget")
	}
}

// For ten minutes after a handshake to a name failed, only the fingerprint
// it failed with may go to that name again.
func TestHandshakeGateHoldsFingerprintAfterFailure(t *testing.T) {
	g, now := fakeGate(time.Unix(1_800_000_000, 0))
	ctx := context.Background()
	gap := g.begin("a.example")
	g.done(ctx, "p", "a.example", "", gap, errors.New("reset")) // "" is chrome
	*now = now.Add(5 * time.Minute)
	if err := reserveNow(g, "a.example", "firefox"); !errors.Is(err, ErrHandshakePaced) {
		t.Fatalf("another fingerprint 5 min after a failure: %v, want ErrHandshakePaced", err)
	}
	if !g.held("a.example", "firefox") {
		t.Fatal("held does not report the fingerprint hold")
	}
	if err := reserveNow(g, "a.example", "Chrome"); err != nil {
		t.Fatalf("the same fingerprint: %v", err)
	}
	if err := reserveNow(g, "b.example", "firefox"); err != nil {
		t.Fatalf("another name: %v", err)
	}
	*now = now.Add(5*time.Minute + time.Second)
	if err := reserveNow(g, "a.example", "firefox"); err != nil {
		t.Fatalf("another fingerprint after the hold: %v", err)
	}
	// A handshake its caller abandoned is no failure.
	g2, _ := fakeGate(time.Unix(1_800_000_000, 0))
	g2.done(ctx, "p", "a.example", "chrome", g2.begin("a.example"), context.Canceled)
	if err := reserveNow(g2, "a.example", "firefox"); err != nil {
		t.Fatalf("after an abandoned handshake: %v", err)
	}
}

// The second paced handshake waits out the gap instead of failing when its
// context allows.
func TestHandshakeGateWaitsTheShortGap(t *testing.T) {
	g := newHSGate()
	g.jitter = func() time.Duration { return 0 }
	if _, err := g.reserve(context.Background(), "a.example", ""); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := g.reserve(context.Background(), "a.example", ""); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 900*time.Millisecond || d > 1500*time.Millisecond {
		t.Fatalf("waited %v, want about 1 s", d)
	}
	// One given up on while waiting leaves its slot.
	g2 := newHSGate()
	g2.jitter = func() time.Duration { return 0 }
	g2.reserve(context.Background(), "a.example", "")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	if _, err := g2.reserve(ctx, "a.example", ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled while waiting: %v", err)
	}
	if n := len(g2.names["a.example"].slots); n != 1 {
		t.Fatalf("%d slots after a cancelled wait, want 1", n)
	}
}

// dialSecure reports each handshake with the gap since the previous one to
// the name and how it ended; a paced dial past the window makes no connection
// at all; a refused TCP connect is not a handshake.
func TestDialSecureCountsAndPacesHandshakes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close() // the ClientHello meets a closed door
		}
	}()
	type seen struct {
		path string
		gap  int64
		end  HandshakeEnd
	}
	var mu sync.Mutex
	var got []seen
	WatchHandshakes(func(path string, gapMs int64, end HandshakeEnd) {
		mu.Lock()
		got = append(got, seen{path, gapMs, end})
		mu.Unlock()
	})
	defer WatchHandshakes(nil)

	g := newHSGate()
	g.jitter = func() time.Duration { return 0 }
	port := ln.Addr().(*net.TCPAddr).Port
	spec := PathSpec{ID: "kv", Kind: KindKilvater, Host: "127.0.0.1", Port: port, SNI: "gate.example", Security: "tls"}
	ctx := context.Background()

	if _, err := dialSecureVia(ctx, g, spec, false, false); err == nil {
		t.Fatal("handshake with a closed door succeeded")
	}
	if _, err := dialSecureVia(ctx, g, spec, false, true); err == nil || errors.Is(err, ErrHandshakePaced) {
		t.Fatalf("first paced handshake: %v, want its own failure", err)
	}
	if _, err := dialSecureVia(ctx, g, spec, false, true); err == nil || errors.Is(err, ErrHandshakePaced) {
		t.Fatalf("second paced handshake: %v, want its own failure after the gap", err)
	}
	before := accepted.Load()
	if _, err := dialSecureVia(ctx, g, spec, false, true); !errors.Is(err, ErrHandshakePaced) {
		t.Fatalf("third paced handshake in a minute: %v, want ErrHandshakePaced", err)
	}
	// Another fingerprint to the name that just failed is refused as well.
	other := spec
	other.SNI, other.Fingerprint = "gate.example", "firefox"
	g.forgetSlots("gate.example")
	if _, err := dialSecureVia(ctx, g, other, false, true); !errors.Is(err, ErrHandshakePaced) {
		t.Fatalf("another fingerprint after a failure: %v, want ErrHandshakePaced", err)
	}
	if n := accepted.Load(); n != before {
		t.Fatalf("a refused handshake still connected: %d connections, was %d", n, before)
	}
	// Unpaced wires are counted, never held.
	if _, err := dialSecureVia(ctx, g, spec, false, false); errors.Is(err, ErrHandshakePaced) {
		t.Fatal("an unpaced handshake was held")
	}
	// A TCP connect that fails takes no slot and is no handshake.
	dead := spec
	dead.SNI, dead.Port = "dead.example", 1
	for i := 0; i < 3; i++ {
		if _, err := dialSecureVia(ctx, g, dead, false, true); err == nil || errors.Is(err, ErrHandshakePaced) {
			t.Fatalf("failed connect %d: %v", i, err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 4 {
		t.Fatalf("%d handshakes reported, want 4: %+v", len(got), got)
	}
	if got[0].gap != -1 || got[0].path != "kv" || got[0].end != HandshakeFail {
		t.Fatalf("first: %+v", got[0])
	}
	if got[1].gap < 0 || got[1].gap > 500 {
		t.Fatalf("second came right after the first, reported gap %d ms", got[1].gap)
	}
	if got[2].gap < 900 || got[2].gap > 1600 {
		t.Fatalf("third waited out the gap, reported %d ms, want about 1000", got[2].gap)
	}
}

// forgetSlots empties name's window and keeps the rest (tests).
func (g *hsGate) forgetSlots(name string) {
	g.mu.Lock()
	if h := g.names[name]; h != nil {
		h.slots = nil
	}
	g.mu.Unlock()
}

// pacedDialer refuses with ErrHandshakePaced once told to.
type pacedDialer struct {
	h2EchoDialer
	hold atomic.Bool
}

func (d *pacedDialer) dial(ctx context.Context) (net.Conn, error) {
	if d.hold.Load() {
		return nil, ErrHandshakePaced
	}
	return d.h2EchoDialer.dial(ctx)
}

// Past its rotation limit, a connection goes on taking streams while the
// handshake for the next one is held back, and rotates once it is not.
func TestH2MuxStaysOnConnectionWhileHandshakeHeld(t *testing.T) {
	d := &pacedDialer{}
	m := newH2Mux(d.dial, 0, 0)
	m.maxAge = 50 * time.Millisecond
	m.held = d.hold.Load
	defer m.Close()

	a := openOrFail(t, m)
	echo(t, a, "first")
	a.Close()
	time.Sleep(90 * time.Millisecond) // past maxAge
	d.hold.Store(true)

	b := openOrFail(t, m)
	echo(t, b, "second")
	b.Close()
	if got := d.count(); got != 1 {
		t.Fatalf("%d dials while held, want the 1 connection kept", got)
	}
	// A refresh while held checks the connection instead of dropping it.
	m.refresh(time.Now())
	c := openOrFail(t, m)
	echo(t, c, "third")
	c.Close()
	if got := d.count(); got != 1 {
		t.Fatalf("%d dials after a refresh while held, want 1", got)
	}

	d.hold.Store(false)
	e := openOrFail(t, m)
	echo(t, e, "fourth")
	e.Close()
	if got := d.count(); got != 2 {
		t.Fatalf("%d dials once the hold was over, want the rotation (2)", got)
	}
}

// With no connection at all, a held handshake is an error the caller can
// tell from a broken path.
func TestH2MuxHeldHandshakeIsTold(t *testing.T) {
	d := &pacedDialer{}
	d.hold.Store(true)
	m := newH2Mux(d.dial, 0, 0)
	defer m.Close()
	_, err := m.openStream(context.Background(), "POST", "https://x.example/", nil)
	if !errors.Is(err, ErrHandshakePaced) {
		t.Fatalf("openStream: %v, want ErrHandshakePaced", err)
	}
}
