package kilvater

// Regression tests for the low-level audit of 2026-11-16 (KL-01, KL-02,
// KL-03, KL-04, KL-07, KL-11).

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func klServer() *Server {
	return &Server{
		Verifier: NewVerifier(nil), Metrics: NewMetrics(nil), ResumeGrace: DefaultResumeGrace,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			a, b := net.Pipe()
			go io.Copy(io.Discard, b)
			return a, nil
		},
	}
}

// KL-01: chunks at offsets one byte apart must not be kept past the window.
func TestBondOutOfOrderCapped(t *testing.T) {
	b := NewBond()
	defer b.Close()
	c1, c2 := net.Pipe()
	go b.RunLeg(c1, true)
	go io.Copy(io.Discard, c2)
	payload := make([]byte, 8+bondChunk)
	for off := uint64(1); off <= 1024; off++ {
		binary.BigEndian.PutUint64(payload, off)
		if err := WriteFrame(c2, FrameSeq, payload); err != nil {
			t.Fatal(err)
		}
	}
	WriteFrame(c2, FramePad, nil)
	time.Sleep(100 * time.Millisecond)
	b.mu.Lock()
	held := b.oooBytes
	b.mu.Unlock()
	if held > bondWindow+bondChunk {
		t.Fatalf("out of order: %d bytes held, cap %d", held, bondWindow+bondChunk)
	}
	if held == 0 {
		t.Fatal("nothing kept: the cap drops honest chunks too")
	}
}

// KL-02: one key may not take the whole bond table.
func TestBondMaxPerKey(t *testing.T) {
	s := klServer()
	s.BondMaxPerKey = 8
	old := bondIdle
	bondIdle = time.Hour
	defer func() { bondIdle = old }()
	join := func(label string, i int) byte {
		var sid [SessionIDLen]byte
		binary.BigEndian.PutUint64(sid[:], uint64(i))
		copy(sid[8:], label)
		body, _ := AppendJoin(nil, sid, JoinCreate, NetTCP, "example.com:443")
		upR, upW := io.Pipe()
		downR, downW := io.Pipe()
		done := make(chan struct{})
		go func() { s.join(label, body, upR, downW, nil); downW.Close(); close(done) }()
		typ, fb, err := ReadFrame(downR, nil)
		go io.Copy(io.Discard, downR)
		upW.Close()
		<-done
		if err != nil || typ != FrameClose {
			return 0xff
		}
		return fb[0]
	}
	defer func() {
		bonds.mu.Lock()
		for k, sb := range bonds.m {
			sb.b.Abort(1, errBondClosed)
			bonds.drop(k, sb)
		}
		n := len(bonds.perKey)
		bonds.mu.Unlock()
		if n != 0 {
			t.Errorf("per-key counts left after the table emptied: %d", n)
		}
	}()
	for i := 0; i < 8; i++ {
		if c := join("a", i); c != 0xff {
			t.Fatalf("bond %d of key a refused with %d", i, c)
		}
	}
	if c := join("a", 8); c != 2 {
		t.Fatalf("bond past the per-key cap: got %#x, want CLOSE 2", c)
	}
	if c := join("b", 1); c != 0xff {
		t.Fatalf("another key's bond refused with %d", c)
	}
}

func klFlow(s *Server, label string, i int, _ bool) (sessKey, *io.PipeWriter, chan struct{}) {
	var sid SessionID
	binary.BigEndian.PutUint64(sid[:], uint64(i))
	upR, upW := io.Pipe()
	downR, downW := io.Pipe()
	go io.Copy(io.Discard, downR) // reads, never confirms
	key := sessKey{label, sid}
	done := make(chan struct{})
	go func() { s.tcpSession(context.Background(), "example.com:443", key, upR, downW, nil); close(done) }()
	return key, upW, done
}

// KL-03: a key's attached flows hold no more than its budget (plus one read
// each), not a window each.
func TestResumeMaxBytesPerKey(t *testing.T) {
	s := klServer()
	s.ResumeMaxBytesPerKey = 1 << 20
	s.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		a, b := net.Pipe()
		go func() {
			p := make([]byte, 32<<10)
			for {
				if _, err := b.Write(p); err != nil {
					return
				}
			}
		}()
		return a, nil
	}
	const streams = 32
	var ups []*io.PipeWriter
	for i := 0; i < streams; i++ {
		_, w, _ := klFlow(s, "k", i, true)
		ups = append(ups, w)
	}
	time.Sleep(1500 * time.Millisecond)
	held := s.sess.held.Load()
	for _, w := range ups {
		w.Close()
	}
	if max := s.ResumeMaxBytesPerKey + streams*(32<<10); held > max {
		t.Fatalf("%d bytes held for one key, budget %d (+ one read per flow: %d)", held, s.ResumeMaxBytesPerKey, max)
	}
	if held == 0 {
		t.Fatal("nothing read")
	}
}

// KL-04: one key may not take every waiting place.
func TestResumeMaxKeptPerKey(t *testing.T) {
	s := klServer()
	s.ResumeMaxKept = 64
	s.ResumeMaxKeptPerKey = 8
	lose := func(label string, i int) *session {
		key, w, done := klFlow(s, label, i, false)
		for s.sess.get(key) == nil {
			time.Sleep(time.Millisecond)
		}
		se := s.sess.get(key)
		w.CloseWithError(io.ErrUnexpectedEOF)
		<-done
		return se
	}
	for i := 0; i < 64; i++ {
		lose("a", i)
	}
	if k := s.sess.kept.Load(); k != 8 {
		t.Fatalf("key a keeps %d flows, cap 8", k)
	}
	se := lose("b", 1)
	se.mu.Lock()
	closed := se.closed
	se.mu.Unlock()
	if closed {
		t.Fatal("another key's flow was not kept")
	}
}

// KL-07: a tag has one spelling.
func TestTagStrictBase64(t *testing.T) {
	var k Key
	rand.Read(k[:])
	v := NewVerifier([]Key{k})
	now := time.Now()
	tag := NewTag(k, "/x", now)
	const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for i := 0; i < len(abc); i++ {
		if abc[i] == tag[len(tag)-1] {
			continue
		}
		if v.Verify(tag[:len(tag)-1]+string(abc[i]), "/x", now) >= 0 {
			t.Fatalf("tag accepted with last character %q", abc[i])
		}
	}
	if v.Verify(tag, "/x", now) < 0 {
		t.Fatal("the tag itself refused")
	}
}

// KL-11: the v1 keys together have a stream cap of their own.
func TestMaxStreamsV1(t *testing.T) {
	s := &Server{Metrics: NewMetrics(nil), MaxStreamsPerKey: 4, MaxStreamsV1: 16}
	n := 0
	for i := 0; i < 100; i++ {
		if _, ok := s.admit(Identity{Index: 0}, time.Now()); ok {
			n++
		}
	}
	if n != 16 {
		t.Fatalf("v1 streams admitted: %d, want 16", n)
	}
	s.MaxStreamsV1 = 0
	if _, ok := s.admit(Identity{Index: 1}, time.Now()); !ok {
		t.Fatal("v1 stream refused with no cap")
	}
}
