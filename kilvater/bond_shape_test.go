package kilvater

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// shapedPipe is one direction of a leg: a bottleneck of rate bytes/s with a
// one-way delay, like a route through a relay (bytes leave the sender at the
// bottleneck's pace and arrive delay later). Writes block while the
// bottleneck queue holds more than queue bytes, as a socket buffer would.
type shapedPipe struct {
	mu     sync.Mutex
	cond   *sync.Cond
	rate   float64
	delay  time.Duration
	queue  int
	queued int
	free   time.Time // when the bottleneck is next idle
	q      []shapedSeg
	buf    []byte
	closed bool
	// freeze holds every byte that would arrive in [freezeAt, freezeAt+freezeFor)
	// until the end of it: a route that stalls (loss, a relay hiccup) but
	// does not die.
	freezeAt  time.Time
	freezeFor time.Duration
	slowRate  float64 // when set, the window above slows the route to this instead
}

type shapedSeg struct {
	at time.Time
	p  []byte
}

func newShapedPipe(rate float64, delay time.Duration) *shapedPipe {
	s := &shapedPipe{rate: rate, delay: delay, queue: 64 << 10}
	s.cond = sync.NewCond(&s.mu)
	go func() {
		t := time.NewTicker(2 * time.Millisecond)
		defer t.Stop()
		for range t.C {
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				return
			}
			now := time.Now()
			if s.slowRate == 0 && !s.freezeAt.IsZero() && !now.Before(s.freezeAt) && now.Before(s.freezeAt.Add(s.freezeFor)) {
				s.mu.Unlock()
				continue
			}
			for len(s.q) > 0 && !s.q[0].at.After(now) {
				s.buf = append(s.buf, s.q[0].p...)
				s.q = s.q[1:]
			}
			// bytes still in the bottleneck (not yet serialized)
			s.queued = 0
			if s.free.After(now) {
				s.queued = int(s.free.Sub(now).Seconds() * s.rate)
			}
			s.cond.Broadcast()
			s.mu.Unlock()
		}
	}()
	return s
}

func (s *shapedPipe) write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for !s.closed && s.queued > s.queue {
		s.cond.Wait()
	}
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	now := time.Now()
	if s.free.Before(now) {
		s.free = now
	}
	rate := s.rate
	if s.slowRate > 0 && !s.free.Before(s.freezeAt) && s.free.Before(s.freezeAt.Add(s.freezeFor)) {
		rate = s.slowRate
	}
	s.free = s.free.Add(time.Duration(float64(len(p)) / rate * float64(time.Second)))
	s.queued += len(p)
	s.q = append(s.q, shapedSeg{at: s.free.Add(s.delay), p: append([]byte(nil), p...)})
	return len(p), nil
}

func (s *shapedPipe) read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.buf) == 0 {
		if s.closed {
			return 0, io.EOF
		}
		s.cond.Wait()
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

func (s *shapedPipe) close() {
	s.mu.Lock()
	s.closed = true
	s.cond.Broadcast()
	s.mu.Unlock()
}

type shapedEnd struct {
	net.Conn
	in, out *shapedPipe
}

func (e *shapedEnd) Read(p []byte) (int, error)  { return e.in.read(p) }
func (e *shapedEnd) Write(p []byte) (int, error) { return e.out.write(p) }
func (e *shapedEnd) Close() error                { e.in.close(); e.out.close(); return nil }

type legShape struct {
	rate  float64 // bytes/s, both ways
	delay time.Duration
	queue int // bottleneck/socket buffer; 0 = 64 KiB
	// freeze the a->b direction for freezeFor, freezeAt after the start
	freezeAt, freezeFor time.Duration
	slowRate            float64
}

// shapedThroughput sends n bytes a->b over legs shaped as given and returns
// bytes per second.
func shapedThroughput(t *testing.T, n int, shapes []legShape) float64 {
	return shapedThroughputOld(t, n, shapes, false)
}

// shapedThroughputOld is shapedThroughput with a receiver that speaks as an
// end without [leg] in its ACKs, if old.
func shapedThroughputOld(t *testing.T, n int, shapes []legShape, old bool) float64 {
	t.Helper()
	a, b := NewBond(), NewBond()
	b.ackNoLeg = old
	t.Cleanup(func() { a.Close(); b.Close() })
	for _, s := range shapes {
		ab, ba := newShapedPipe(s.rate, s.delay), newShapedPipe(s.rate, s.delay)
		if s.queue > 0 {
			ab.queue, ba.queue = s.queue, s.queue
		}
		if s.freezeFor > 0 {
			ab.freezeAt, ab.freezeFor, ab.slowRate = time.Now().Add(s.freezeAt), s.freezeFor, s.slowRate
		}
		go a.RunLeg(&shapedEnd{in: ba, out: ab}, false)
		go b.RunLeg(&shapedEnd{in: ab, out: ba}, true)
	}
	data := randBytes(n)
	errs := make(chan error, 1)
	start := time.Now()
	sendAll(t, a, data, errs)
	got, err := recvAll(b)
	d := time.Since(start)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("got %d/%d bytes, %v", len(got), len(data), err)
	}
	return float64(n) / d.Seconds()
}

// Two routes of different speed and delay, as CDN relay + VK TURN: the bond
// should come close to the sum of the two.
func TestBondShapedSum(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	cases := []struct {
		name   string
		shapes []legShape
	}{
		{"equal", []legShape{{500 << 10, 40 * time.Millisecond, 0, 0, 0, 0}, {500 << 10, 40 * time.Millisecond, 0, 0, 0, 0}}},
		{"cdn+turn", []legShape{{450 << 10, 60 * time.Millisecond, 0, 0, 0, 0}, {550 << 10, 120 * time.Millisecond, 0, 0, 0, 0}}},
		{"fast+slowfar", []legShape{{800 << 10, 30 * time.Millisecond, 0, 0, 0, 0}, {250 << 10, 200 * time.Millisecond, 0, 0, 0, 0}}},
		// From far away (one-way ~120-200 ms) through deep buffers, as the
		// real legs are: TLS/h2 over TCP, TURN with its own queue.
		{"far", []legShape{{500 << 10, 120 * time.Millisecond, 0, 0, 0, 0}, {450 << 10, 200 * time.Millisecond, 0, 0, 0, 0}}},
		{"far+bufs", []legShape{{500 << 10, 120 * time.Millisecond, 2 << 20, 0, 0, 0}, {450 << 10, 200 * time.Millisecond, 2 << 20, 0, 0, 0}}},
		{"near+bufs", []legShape{{500 << 10, 40 * time.Millisecond, 2 << 20, 0, 0, 0}, {450 << 10, 60 * time.Millisecond, 2 << 20, 0, 0, 0}}},
		// One route stalls for 3 s twice and comes back: the other should
		// carry the flow meanwhile. The "sum" here is what the routes could
		// deliver over the time: 8 MiB / ideal.
		{"stall8s", []legShape{{500 << 10, 60 * time.Millisecond, 512 << 10, 0, 0, 0}, {500 << 10, 100 * time.Millisecond, 512 << 10, 2 * time.Second, 8 * time.Second, 0}}},
		{"sag", []legShape{{500 << 10, 60 * time.Millisecond, 512 << 10, 0, 0, 0}, {500 << 10, 100 * time.Millisecond, 512 << 10, 2 * time.Second, 6 * time.Second, 50 << 10}}},
		{"stall", []legShape{{500 << 10, 60 * time.Millisecond, 512 << 10, 0, 0, 0}, {500 << 10, 100 * time.Millisecond, 512 << 10, 2 * time.Second, 3 * time.Second, 0}}},
	}
	for _, c := range cases {
		sum := 0.0
		for _, s := range c.shapes {
			sum += s.rate
		}
		got := shapedThroughput(t, 8<<20, c.shapes)
		t.Logf("%-14s %.0f KiB/s of %.0f KiB/s = %.0f%%", c.name, got/1024, sum/1024, 100*got/sum)
	}
}

// An end without [leg] in its ACKs (the server before it) is still served,
// by the in-order point alone, with nothing lost.
func TestBondOldAcks(t *testing.T) {
	shapes := []legShape{{500 << 10, 20 * time.Millisecond, 0, 0, 0, 0}, {300 << 10, 40 * time.Millisecond, 0, 0, 0, 0}}
	got := shapedThroughputOld(t, 2<<20, shapes, true)
	if got < 400<<10 {
		t.Fatalf("%.0f KiB/s against an old end", got/1024)
	}
	t.Logf("old end: %.0f KiB/s", got/1024)
}
