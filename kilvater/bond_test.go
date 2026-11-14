package kilvater

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// slowConn delays every write: a leg with a long, thin pipe.
type slowConn struct {
	net.Conn
	delay time.Duration
}

func (c *slowConn) Write(p []byte) (int, error) {
	time.Sleep(c.delay)
	return c.Conn.Write(p)
}

// bondPair joins two bonds by n legs; legs[i] holds both ends of leg i.
func bondPair(t *testing.T, n int, wrap func(i int, c net.Conn) net.Conn) (a, b *Bond, legs [][2]net.Conn) {
	t.Helper()
	a, b = NewBond(), NewBond()
	for i := 0; i < n; i++ {
		x, y := net.Pipe()
		if wrap != nil {
			x, y = wrap(i, x), wrap(i, y)
		}
		legs = append(legs, [2]net.Conn{x, y})
		go a.RunLeg(x, false)
		go b.RunLeg(y, true)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b, legs
}

// sendAll writes p and finishes; recvAll reads to the far end's FIN.
func sendAll(t *testing.T, w *Bond, p []byte, errs chan<- error) {
	go func() {
		for off := 0; off < len(p); {
			n := 7919
			if off+n > len(p) {
				n = len(p) - off
			}
			if _, err := w.Write(p[off : off+n]); err != nil {
				errs <- err
				return
			}
			off += n
		}
		errs <- w.CloseWrite()
	}()
}

func recvAll(r *Bond) ([]byte, error) {
	var out bytes.Buffer
	_, err := io.Copy(&out, r)
	return out.Bytes(), err
}

func randBytes(n int) []byte {
	p := make([]byte, n)
	rand.Read(p)
	return p
}

func TestBondBothWays(t *testing.T) {
	a, b, _ := bondPair(t, 3, nil)
	up, down := randBytes(5<<20), randBytes(3<<20)
	errs := make(chan error, 2)
	sendAll(t, a, up, errs)
	sendAll(t, b, down, errs)
	var wg sync.WaitGroup
	var gotUp, gotDown []byte
	var e1, e2 error
	wg.Add(2)
	go func() { defer wg.Done(); gotUp, e1 = recvAll(b) }()
	go func() { defer wg.Done(); gotDown, e2 = recvAll(a) }()
	wg.Wait()
	if e1 != nil || e2 != nil || !bytes.Equal(gotUp, up) || !bytes.Equal(gotDown, down) {
		t.Fatalf("up %d/%d %v, down %d/%d %v", len(gotUp), len(up), e1, len(gotDown), len(down), e2)
	}
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if !a.Drain(2*time.Second) || !b.Drain(2*time.Second) {
		t.Fatal("drain did not finish")
	}
}

// A leg dropping mid-flow loses nothing: its chunks go out on the others.
func TestBondLegDies(t *testing.T) {
	a, b, legs := bondPair(t, 3, nil)
	data := randBytes(6 << 20)
	errs := make(chan error, 1)
	sendAll(t, a, data, errs)
	go func() {
		time.Sleep(30 * time.Millisecond)
		legs[1][0].Close()
	}()
	got, err := recvAll(b)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("got %d/%d bytes, %v", len(got), len(data), err)
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
}

// A slow leg does not hold the flow back to its pace.
func TestBondSlowLeg(t *testing.T) {
	a, b, _ := bondPair(t, 2, func(i int, c net.Conn) net.Conn {
		if i == 1 {
			return &slowConn{Conn: c, delay: 20 * time.Millisecond}
		}
		return c
	})
	data := randBytes(4 << 20)
	errs := make(chan error, 1)
	start := time.Now()
	sendAll(t, a, data, errs)
	got, err := recvAll(b)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("got %d/%d bytes, %v", len(got), len(data), err)
	}
	// 4 MiB in 16 KiB frames over the slow leg alone would take ~5 s.
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("took %v", d)
	}
}

// A far end that fails closes the flow with ErrBondFailed, not EOF.
func TestBondAbort(t *testing.T) {
	a, b, _ := bondPair(t, 2, nil)
	if _, err := a.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 1)
	if _, err := io.ReadFull(b, p); err != nil {
		t.Fatal(err)
	}
	b.Abort(1, io.ErrUnexpectedEOF)
	done := make(chan error, 1)
	go func() { _, err := a.Read(p); done <- err }()
	select {
	case err := <-done:
		if err != ErrBondFailed {
			t.Fatalf("read %v, want ErrBondFailed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the abort did not reach the other end")
	}
}

func TestJoinRoundTrip(t *testing.T) {
	var id [SessionIDLen]byte
	rand.Read(id[:])
	body, err := AppendJoin(nil, id, JoinCreate, NetTCP, "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	gid, f, n, addr, err := ParseJoin(body)
	if err != nil || gid != id || f != JoinCreate || n != NetTCP || addr != "example.com:443" {
		t.Fatalf("%x %d %d %q %v", gid, f, n, addr, err)
	}
	if _, _, _, _, err := ParseJoin(body[:10]); err == nil {
		t.Fatal("short JOIN parsed")
	}
}
