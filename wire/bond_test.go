package wire

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
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

// bondOver builds a bond whose legs all reach one in-process server; a nil
// entry in dead makes that leg's dial fail.
func bondOver(t *testing.T, legs int, dead map[int]bool) *bondWire {
	t.Helper()
	key, hexKey := kilTestKey(t)
	srv := kilServerFor(key)
	var ws []*kilWire
	for i := 0; i < legs; i++ {
		i := i
		w, err := newKilWire(kilTestSpec(hexKey), func(ctx context.Context) (net.Conn, error) {
			if dead[i] {
				return nil, errors.New("leg down")
			}
			c, s := net.Pipe()
			t.Cleanup(func() { s.Close() })
			go (&http2.Server{}).ServeConn(s, &http2.ServeConnOpts{Handler: srv})
			return c, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		ws = append(ws, w)
	}
	bw := &bondWire{spec: PathSpec{ID: "bond", Kind: KindBond}, legs: ws, stats: make([]legCount, len(ws))}
	t.Cleanup(func() { bw.Close() })
	return bw
}

func TestBondFlow(t *testing.T) {
	flowEchoOver(t, bondOver(t, 2, nil))
}

// One leg that never opens does not stop the flow.
func TestBondFlowDeadLeg(t *testing.T) {
	flowEchoOver(t, bondOver(t, 3, map[int]bool{0: true}))
}

// A few megabytes cross the bond and come back from the echo intact.
func TestBondBulk(t *testing.T) {
	w := bondOver(t, 3, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sess, err := w.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port := echoTCP(t)
	data := make([]byte, 3<<20)
	rand.Read(data)
	up := make(chan []byte, 4)
	pr, pw := io.Pipe()
	go func() {
		sess.Run(ctx, Target{Host: "127.0.0.1", Port: port}, nil, up, pw, nopMeter{})
		pw.Close()
	}()
	go func() {
		for off := 0; off < len(data); off += 32 << 10 {
			end := off + 32<<10
			if end > len(data) {
				end = len(data)
			}
			up <- data[off:end]
		}
	}()
	got := make([]byte, len(data))
	if _, err := io.ReadFull(pr, got); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("echo came back wrong (%v)", err)
	}
	close(up)
}

// A server whose kilvater does not know JOIN closes the leg unanswered; with
// every leg like that the path is dead, not the flow.
func TestBondOldServer(t *testing.T) {
	key, hexKey := kilTestKey(t)
	srv := kilServerFor(key)
	old := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			rw.WriteHeader(200)
			rw.(http.Flusher).Flush()
			kilvater.ReadFrame(r.Body, nil) // the JOIN: not understood, the stream ends
			return
		}
		srv.ServeHTTP(rw, r)
	})
	var ws []*kilWire
	for i := 0; i < 2; i++ {
		w, err := newKilWire(kilTestSpec(hexKey), func(ctx context.Context) (net.Conn, error) {
			c, s := net.Pipe()
			t.Cleanup(func() { s.Close() })
			go (&http2.Server{}).ServeConn(s, &http2.ServeConnOpts{Handler: old})
			return c, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		ws = append(ws, w)
	}
	bw := &bondWire{spec: PathSpec{ID: "bond", Kind: KindBond}, legs: ws, stats: make([]legCount, len(ws))}
	defer bw.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := bw.Dial(ctx)
	if err != nil {
		t.Skipf("the old server refused the stream outright: %v", err)
	}
	up := make(chan []byte)
	o, err := sess.Run(ctx, Target{Host: "127.0.0.1", Port: echoTCP(t)}, []byte("hi"), up, io.Discard, nopMeter{})
	if !errors.Is(err, ErrWireDead) {
		t.Fatalf("outcome %v, %v; want ErrWireDead", o, err)
	}
}

func TestBondParse(t *testing.T) {
	leg := func(host string) string {
		return base64.RawURLEncoding.EncodeToString([]byte("kilvater://" + testOlcKey + "@" + host + ":443/connect?sni=" + host + "#l"))
	}
	spec, err := ParseURI("kilbond://x?leg=" + leg("a.test") + "&leg=" + leg("b.test") + "#bond%20one")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Kind != KindBond || len(spec.Legs) != 2 || spec.ID != "bond one" || spec.Host != "a.test" || spec.Legs[1].Host != "b.test" {
		t.Fatalf("%+v", spec)
	}
	if _, err := ParseURI("kilbond://x?leg=" + leg("a.test")); err == nil {
		t.Fatal("one leg parsed")
	}
	trojan := base64.RawURLEncoding.EncodeToString([]byte("trojan://pw@a.test:443#t"))
	if _, err := ParseURI("kilbond://x?leg=" + leg("a.test") + "&leg=" + trojan); err == nil {
		t.Fatal("a trojan leg parsed")
	}
}

// legCtl lets a test drop one leg's route and bring it back.
type legCtl struct {
	mu    sync.Mutex
	down  bool
	conns []net.Conn
	dials int   // successful dials
	read  int64 // bytes the client read on this leg's connections
}

type legCountConn struct {
	net.Conn
	c *legCtl
}

func (cc legCountConn) Read(p []byte) (int, error) {
	n, err := cc.Conn.Read(p)
	cc.c.mu.Lock()
	cc.c.read += int64(n)
	cc.c.mu.Unlock()
	return n, err
}

// cut drops the route: the live connections die and new dials fail.
func (c *legCtl) cut() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.down = true
	for _, x := range c.conns {
		x.Close()
	}
	c.conns = nil
}

func (c *legCtl) heal() (dials int, read int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.down = false
	return c.dials, c.read
}

func (c *legCtl) now() (int, int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dials, c.read
}

func bondCtl(t *testing.T, ctl []*legCtl) *bondWire {
	t.Helper()
	key, hexKey := kilTestKey(t)
	srv := kilServerFor(key)
	var ws []*kilWire
	for _, c := range ctl {
		c := c
		w, err := newKilWire(kilTestSpec(hexKey), func(ctx context.Context) (net.Conn, error) {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.down {
				return nil, errors.New("route down")
			}
			a, s := net.Pipe()
			t.Cleanup(func() { s.Close() })
			go (&http2.Server{}).ServeConn(s, &http2.ServeConnOpts{Handler: srv})
			c.conns = append(c.conns, a)
			c.dials++
			return legCountConn{a, c}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		ws = append(ws, w)
	}
	bw := &bondWire{spec: PathSpec{ID: "bond", Kind: KindBond}, legs: ws, stats: make([]legCount, len(ws))}
	t.Cleanup(func() { bw.Close() })
	return bw
}

func shrunk(w *bondWire, rejoins int) *bondWire {
	w.tune = &bondTune{20 * time.Millisecond, 80 * time.Millisecond, bondLegTries, rejoins, bondLegRejoinsAlone}
	return w
}

// pacedEcho sends size bytes in 16 KiB pieces every gap and checks they come
// back whole; during(t) runs while the flow is on.
func pacedEcho(t *testing.T, w *bondWire, size int, gap time.Duration, during func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sess, err := w.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, size)
	rand.Read(data)
	up := make(chan []byte, 4)
	pr, pw := io.Pipe()
	ran := make(chan struct{})
	defer func() { cancel(); <-ran }() // the legs are gone before the test's vars are put back
	go func() {
		defer close(ran)
		sess.Run(ctx, Target{Host: "127.0.0.1", Port: echoTCP(t)}, nil, up, pw, nopMeter{})
		pw.Close()
	}()
	go func() {
		for off := 0; off < len(data); off += 16 << 10 {
			up <- data[off:min(off+16<<10, len(data))]
			time.Sleep(gap)
		}
	}()
	go during()
	got := make([]byte, len(data))
	if _, err := io.ReadFull(pr, got); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("echo came back wrong (%v)", err)
	}
	close(up)
}

// A leg whose route drops mid-flow and stays down for a while comes back into
// the same flow once the route is back (before 16.11 one failed reopen let it
// go for the rest of the flow); the flow never breaks.
func TestBondLegRejoinsAfterOutage(t *testing.T) {
	ctl := []*legCtl{{}, {}}
	var afterDials int
	var afterRead int64
	done := make(chan struct{})
	w := shrunk(bondCtl(t, ctl), 50)
	pacedEcho(t, w, 1<<20, 25*time.Millisecond, func() {
		defer close(done)
		time.Sleep(300 * time.Millisecond)
		ctl[1].cut()
		time.Sleep(400 * time.Millisecond) // several reopens fail meanwhile
		afterDials, afterRead = ctl[1].heal()
	})
	<-done
	d, r := ctl[1].now()
	if d <= afterDials || r <= afterRead {
		t.Fatalf("leg 1 never came back: dials %d→%d, read %d→%d", afterDials, d, afterRead, r)
	}
	st := w.BondStats()
	if len(st) != 2 || st[1].Drops < 1 || st[1].Backs < 1 || st[1].Fails < 1 || st[0].Down == 0 || st[1].Down == 0 {
		t.Fatalf("leg stats don't show the outage: %+v", st)
	}
}

// A leg that stays down past bondLegRejoins is let go; the flow finishes on
// the other leg.
func TestBondLegLetGoFlowLives(t *testing.T) {
	ctl := []*legCtl{{}, {}}
	var at int
	done := make(chan struct{})
	pacedEcho(t, shrunk(bondCtl(t, ctl), 3), 1<<20, 20*time.Millisecond, func() {
		defer close(done)
		time.Sleep(200 * time.Millisecond)
		ctl[1].cut()
		time.Sleep(600 * time.Millisecond) // 3 reopens × ≤80 ms: given up
		at, _ = ctl[1].heal()
	})
	<-done
	if d, _ := ctl[1].now(); d != at {
		t.Fatalf("leg 1 dialed again after it was let go: %d→%d", at, d)
	}
}

// When no other leg carries, a dropped leg stops after bondLegRejoinsAlone and
// the flow ends instead of hanging on a server that lost the bond.
func TestBondAloneLegGivesUp(t *testing.T) {
	ctl := []*legCtl{{}}
	w := shrunk(bondCtl(t, ctl), 50)
	w.legs = append(w.legs, w.legs[0]) // satisfy two legs on one route
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := w.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	up := make(chan []byte)
	res := make(chan error, 1)
	go func() {
		_, err := sess.Run(ctx, Target{Host: "127.0.0.1", Port: echoTCP(t)}, []byte("hi"), up, io.Discard, nopMeter{})
		res <- err
	}()
	defer func() { cancel(); <-res }()
	time.Sleep(300 * time.Millisecond)
	ctl[0].cut()
	select {
	case err := <-res:
		res <- err
	case <-time.After(3 * time.Second):
		t.Fatal("flow hung with every route down")
	}
}
