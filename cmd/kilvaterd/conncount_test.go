package main

import (
	"net"
	"testing"

	"github.com/tsyrenov1987/farvater-core/kilvater"
)

type connCounter struct{ open, total int }

func (c *connCounter) ConnOpened() { c.open++; c.total++ }
func (c *connCounter) ConnClosed() { c.open-- }

var _ interface {
	ConnOpened()
	ConnClosed()
} = (*kilvater.Metrics)(nil)

// The listener's own count falls when a connection closes, however many times
// Close is called — the h2c path's connections never reach ConnState's
// StateClosed.
func TestCountConnsFallsOnClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var cc connCounter
	cl := countConns(ln, &cc)
	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err == nil {
			c.Close()
		}
	}()
	c, err := cl.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if cc.open != 1 || cc.total != 1 {
		t.Fatalf("after accept: open=%d total=%d, want 1, 1", cc.open, cc.total)
	}
	c.Close()
	c.Close()
	if cc.open != 0 {
		t.Fatalf("after close: open=%d, want 0", cc.open)
	}
}
