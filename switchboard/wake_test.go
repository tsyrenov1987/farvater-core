package switchboard

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/wire"
)

// answeredOnce answers one TLS record, then the remote goes silent.
type answeredOnce struct{}

func (answeredOnce) Run(ctx context.Context, _ wire.Target, _ []byte, _ <-chan []byte, _ io.Writer, m wire.Meter) (wire.Outcome, error) {
	m.Down(record(200))
	<-ctx.Done()
	return wire.OutcomeCanceled, ctx.Err()
}
func (answeredOnce) Close() error { return nil }

// After the phone sleeps, a connection the app kept open has often lost its
// NAT entry: a request on it waits in silence until the app's own timeout,
// half a minute or more, and the phone looks offline after unlocking. A flow
// open across the sleep that asked and got nothing back for as long as a new
// flow waits for its first byte is closed, so the app reconnects at once. Awake,
// or while the app keeps sending (an upload), the flow is left alone.
func TestRequestOnAConnectionThatSleptIsClosed(t *testing.T) {
	run := func(slept bool, uploading bool) (ended bool, fbTimeout bool) {
		f := &flow{s: &Switchboard{cfg: DefaultConfig()}, fbDeadlineMs: 300, up: make(chan []byte)}
		a := f.newAttempt("p", false)
		if slept {
			labSleep = func(start, _ time.Time) time.Duration {
				if start.Equal(a.start) {
					return 60 * time.Second
				}
				return 0
			}
			defer func() { labSleep = nil }()
		}
		done := make(chan bool, 1)
		go func() {
			_, _, fb, _ := f.run(context.Background(), answeredOnce{}, a, nil)
			done <- fb
		}()
		time.Sleep(100 * time.Millisecond)
		a.m.Up(record(300)) // the app asks on the old connection
		stop := time.After(3500 * time.Millisecond)
		up := time.NewTicker(100 * time.Millisecond)
		defer up.Stop()
		for {
			select {
			case fb := <-done:
				return true, fb
			case <-up.C:
				if uploading {
					a.m.Up(record(300))
				}
			case <-stop:
				return false, false
			}
		}
	}
	if ended, fb := run(true, false); !ended || !fb {
		t.Fatalf("slept, asked, nothing back: ended %v (first-byte timeout %v); want closed within 3.5 s", ended, fb)
	}
	if ended, _ := run(false, false); ended {
		t.Fatal("awake: an answered flow waiting on a request was closed")
	}
	if ended, _ := run(true, true); ended {
		t.Fatal("slept: a flow the app keeps sending on was closed")
	}
}
