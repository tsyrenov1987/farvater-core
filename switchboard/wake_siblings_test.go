package switchboard

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/wire"
)

// answersAt answers one TLS record at once and, after late, one more; then the
// remote goes silent.
type answersAt struct{ late time.Duration }

func (s answersAt) Run(ctx context.Context, _ wire.Target, _ []byte, _ <-chan []byte, _ io.Writer, m wire.Meter) (wire.Outcome, error) {
	m.Down(record(200))
	if s.late > 0 {
		select {
		case <-time.After(s.late):
			m.Down(record(200))
		case <-ctx.Done():
			return wire.OutcomeCanceled, ctx.Err()
		}
	}
	<-ctx.Done()
	return wire.OutcomeCanceled, ctx.Err()
}
func (answersAt) Close() error { return nil }

// An app keeps several connections open; the phone sleeps and the network
// forgets them all. Each one the app picks up again after waking waits in
// silence until the core closes it, a first-byte deadline each: in the lab the
// first loads after waking took 4-9 s, again and again. Once one of them asked
// and heard nothing back, the others on that path that slept with it and have
// heard nothing since are closed at once, so the app reconnects them before it
// asks. A connection that did not sleep, one on another path and one that
// heard from the far end after waking are left alone.
func TestConnectionsThatSleptAreClosedOnceOneProvesThemGone(t *testing.T) {
	type other struct {
		path  string
		slept bool
		late  time.Duration // the far end answers again this long after the start
	}
	run := func(o other) (ended bool) {
		s := &Switchboard{cfg: DefaultConfig()}
		proof := &flow{s: s, fbDeadlineMs: 300, up: make(chan []byte)}
		idle := &flow{s: s, fbDeadlineMs: 300, up: make(chan []byte)}
		pa := proof.newAttempt("p", false)
		ia := idle.newAttempt(o.path, false)
		sleep := func(start, _ time.Time) time.Duration {
			if start.Equal(pa.start) || o.slept && start.Equal(ia.start) {
				return 60 * time.Second
			}
			return 0
		}
		labSleep.Store(&sleep)
		ctx, cancel := context.WithCancel(context.Background())
		proofDone, idleDone := make(chan bool, 1), make(chan bool, 1)
		var wg sync.WaitGroup
		defer func() { cancel(); wg.Wait(); labSleep.Store(nil) }()
		wg.Go(func() {
			_, _, fb, _ := proof.run(ctx, answersAt{}, pa, nil)
			proofDone <- fb
		})
		wg.Go(func() {
			idle.run(ctx, answersAt{o.late}, ia, nil)
			idleDone <- true
		})
		time.Sleep(100 * time.Millisecond)
		pa.m.Up(record(300)) // the app asks on one old connection
		select {
		case fb := <-proofDone:
			if !fb {
				t.Fatal("the connection that asked was not closed on its first-byte deadline")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("the connection that asked was not closed within 3 s")
		}
		select {
		case <-idleDone:
			return true
		case <-time.After(2500 * time.Millisecond):
			return false
		}
	}
	if !run(other{path: "p", slept: true}) {
		t.Fatal("another connection that slept on the same path stayed open after one proved them gone")
	}
	if run(other{path: "p", slept: false}) {
		t.Fatal("a connection opened after the sleep was closed")
	}
	if run(other{path: "q", slept: true}) {
		t.Fatal("a connection on another path was closed")
	}
	if run(other{path: "p", slept: true, late: 600 * time.Millisecond}) {
		t.Fatal("a connection that heard from the far end after waking was closed")
	}
}
