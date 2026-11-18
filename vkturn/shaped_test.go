package vkturn

import (
	"net"
	"testing"
	"time"
)

type sinkConn struct {
	net.Conn
	n int
}

func (s *sinkConn) Write(p []byte) (int, error) { s.n += len(p); return len(p), nil }

// The data goes into KCP at Share of the channels' rate, and with no channels'
// rate known it is not held at all.
func TestShapedHoldsTheRate(t *testing.T) {
	sink := &sinkConn{}
	rate := 400e3
	c := &shaped{Conn: sink, rate: func() float64 { return rate }}
	start := time.Now()
	if n, err := c.Write(make([]byte, 100e3)); n != 100e3 || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	want := time.Duration(100e3 / (rate * Share) * float64(time.Second)) // ~294 ms
	if d := time.Since(start); d < want*8/10 || d > want*2 {
		t.Fatalf("100 kB at %.0f B/s took %v, want about %v", rate*Share, d, want)
	}
	rate = 0
	start = time.Now()
	c.Write(make([]byte, 100e3))
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("with no rate the write waited %v", d)
	}
	if sink.n != 200e3 {
		t.Fatalf("passed on %d bytes", sink.n)
	}
}
