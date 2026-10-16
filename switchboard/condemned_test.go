package switchboard

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/brain"
	"github.com/tsyrenov1987/farvater-core/catalogue"
)

// A TSPU box freezing a path holds its flows open in silence. The breaker
// condemns the path within seconds and new flows go elsewhere, but the flows
// already frozen on it wait until the app's own timeout, half a minute on
// many: a video that stops and stays stopped. Once the path is condemned, a
// flow on it that stalled or asked and got nothing back for as long as a new
// flow waits for its first byte is closed, so the app reconnects at once. On a
// path not condemned the same flow is left to the stall watchdog.
func TestStuckFlowOnACondemnedPathIsClosed(t *testing.T) {
	cat, err := catalogue.Parse([]byte("vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?security=tls&sni=a.example.com&type=tcp#a"))
	if err != nil {
		t.Fatal(err)
	}
	run := func(condemn bool, whole bool, asks bool) bool {
		cfg := DefaultConfig()
		cfg.StallMs = 300
		s, err := New(cfg, cat)
		if err != nil {
			t.Fatal(err)
		}
		id := s.Paths()[0]
		app, client := net.Pipe()
		go io.Copy(io.Discard, app)
		defer app.Close()
		f := &flow{s: s, client: client, fbDeadlineMs: 300, up: make(chan []byte)}
		a := f.newAttempt(id, false)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		defer func() { cancel(); <-done }()
		go func() {
			f.run(ctx, frozenSession{whole}, a, nil)
			close(done)
		}()
		time.Sleep(100 * time.Millisecond)
		if asks {
			a.m.Up(record(300)) // the app asks again on the frozen flow
		}
		if condemn {
			now := nowMs()
			s.mu.Lock()
			for i := 0; i < 3 && !s.b.Breaker.Tripped(id, now); i++ {
				s.b.Breaker.NoteSig(id, brain.SigThrottle, now)
			}
			tripped := s.b.Breaker.Tripped(id, now)
			s.mu.Unlock()
			if !tripped {
				t.Fatal("the test could not trip the path")
			}
		}
		select {
		case <-done:
			return true
		case <-time.After(2500 * time.Millisecond):
			return false
		}
	}
	if !run(true, false, false) {
		t.Fatal("condemned path, flow stalled inside the site's record: still open 2.5 s on")
	}
	if !run(true, true, true) {
		t.Fatal("condemned path, app asked and got nothing back: still open 2.5 s on")
	}
	if run(false, false, false) {
		t.Fatal("healthy path: a stalled flow was closed")
	}
}
