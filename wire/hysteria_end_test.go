package wire

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// countDown hands the app its bytes and calls full once n have come.
type countDown struct {
	n, got int64
	full   func()
	once   atomic.Bool
}

func (d *countDown) Write(p []byte) (int, error) {
	d.got += int64(len(p))
	if d.got >= d.n && d.once.CompareAndSwap(false, true) {
		d.full()
	}
	return len(p), nil
}

// A Hysteria 2 server ends a stream whose target closed by canceling it with
// code 0, "no error": the answer came whole, and the app's last bytes (a TLS
// close_notify) may meet that cancel. A flow that got everything is not a
// reset of the path; the breaker takes a reset as a hard block and drops a
// healthy leader for 90 s.
func TestHysteriaStreamEndIsNotAReset(t *testing.T) {
	port := hysteriaServer(t)
	const answer = 64 << 10
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 64)
				if _, err := io.ReadAtLeast(c, buf, 5); err != nil {
					return
				}
				c.Write(make([]byte, answer)) // the answer, then the target closes
			}()
		}
	}()
	spec, err := ParseURI(fmt.Sprintf("hysteria2://pw@127.0.0.1:%d/?sni=farvater.test&insecure=1#t", port))
	if err != nil {
		t.Fatal(err)
	}
	w, err := Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sess, err := w.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	target := Target{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port}
	bad := 0
	for i := 0; i < 100; i++ {
		up := make(chan []byte, 2)
		d := &countDown{n: answer}
		d.full = func() {
			up <- make([]byte, 31) // the app's close_notify
			close(up)
		}
		o, err := sess.Run(ctx, target, []byte("hello"), up, d, nopMeter{})
		if d.got != answer {
			t.Fatalf("flow %d: %d of %d bytes (%v, %v)", i, d.got, answer, o, err)
		}
		if o == OutcomeError {
			bad++
			t.Logf("flow %d: whole answer, outcome error: %v", i, err)
		}
	}
	if bad > 0 {
		t.Fatalf("%d of 100 flows that got the whole answer ended as an error (a reset)", bad)
	}
}
