package switchboard

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/brain"
	"github.com/tsyrenov1987/farvater-core/catalogue"
)

// The TSPU freezes the leader under the connections the app keeps open: a
// request on one gets nothing back, no record is cut, and the app waits for
// its own timeout, 25 s and more, before it dials again. Two flows on the
// leader that answered quickly until then and have waited 2 s for an answer to
// a request go to the brain as left unanswered; a sweep finds whether the
// leader still delivers, and if it does not, the flows waiting on it are
// closed so the app reconnects to the new leader. A few bytes with no answer
// (an HTTP/2 connection's control frames) are not a request, and on a leader
// that delivers its probe the flows are left alone.
func TestFlowsLeftUnansweredOnAFrozenLeaderAreClosed(t *testing.T) {
	cat, err := catalogue.Parse([]byte("vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?security=tls&sni=a.example.com&type=tcp#a\n" +
		"vless://00000000-0000-0000-0000-000000000000@127.0.0.2:1?security=tls&sni=b.example.com&type=tcp#b"))
	if err != nil {
		t.Fatal(err)
	}
	run := func(ask int, leaderDelivers bool) (noted, closed int) {
		s, err := New(DefaultConfig(), cat)
		if err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		s.b.Pick(nowMs(), "x", brain.DstTLS443)
		lead := s.b.Leader()
		s.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		defer wg.Wait()
		defer cancel()
		ended := make(chan bool, 2)
		var as []*attempt
		for i := 0; i < 2; i++ {
			f := &flow{s: s, fbDeadlineMs: 6000, up: make(chan []byte)}
			a := f.newAttempt(lead, false)
			as = append(as, a)
			wg.Go(func() { f.run(ctx, answeredOnce{}, a, nil); ended <- true })
		}
		time.Sleep(100 * time.Millisecond)
		for _, a := range as {
			a.m.Up(make([]byte, ask)) // the app asks on its open connection
		}
		for end := time.Now().Add(3500 * time.Millisecond); time.Now().Before(end) && noted < 2; time.Sleep(50 * time.Millisecond) {
			s.mu.Lock()
			noted = s.b.J.Count("unanswered")
			s.mu.Unlock()
		}
		if noted < 2 {
			return noted, 0
		}
		s.mu.Lock()
		now := nowMs()
		probed := s.b.SweepDue(now)
		for _, p := range probed {
			if p != lead {
				s.b.Swept(p, 256<<10, 20, true, now+20)
			}
		}
		if leaderDelivers {
			s.b.Swept(lead, 256<<10, 25, true, now+25)
		}
		s.b.SweepCheck(now + 1100)
		s.mu.Unlock()
		for end := time.After(2500 * time.Millisecond); closed < 2; closed++ {
			select {
			case <-ended:
			case <-end:
				return noted, closed
			}
		}
		return noted, closed
	}
	if n, c := run(300, false); n != 2 || c != 2 {
		t.Fatalf("two flows on a frozen leader, a request each unanswered: %d noted, %d closed after the leader failed its probe; want 2 and 2", n, c)
	}
	if n, c := run(300, true); n != 2 || c != 0 {
		t.Fatalf("two flows waiting on a leader that delivers its probe: %d noted, %d closed; want 2 and 0", n, c)
	}
	if n, _ := run(60, false); n != 0 {
		t.Fatalf("60 bytes without an answer (control frames) noted as unanswered on %d flows", n)
	}
}

// A request is reported unanswered once, 2 s after the app sent its last byte
// with nothing back, on a connection that answered quickly until then. Not
// while the app still sends, not for a few bytes, and not on a connection
// whose earlier answer took over 2 s: a long poll's, which waits on a healthy
// path as long as the server has nothing to say.
func TestAskOnceReportsAQuickConnectionLeftUnanswered(t *testing.T) {
	m := newMeter()
	m.Down(record(200))
	m.Up(make([]byte, 300))
	now := nowMs()
	if m.askOnce(now + 1500) {
		t.Fatal("reported 1.5 s after the request")
	}
	if !m.askOnce(now + 2100) {
		t.Fatal("a request unanswered for 2.1 s on a quick connection not reported")
	}
	if m.askOnce(now + 3000) {
		t.Fatal("the same request reported twice")
	}
	m.Down(record(200))
	m.Up(make([]byte, 300))
	if now = nowMs(); !m.askOnce(now + 2100) {
		t.Fatal("the next request, unanswered too, not reported")
	}

	m = newMeter()
	m.Down(record(200))
	m.Up(make([]byte, 60))
	if m.askOnce(nowMs() + 5000) {
		t.Fatal("60 bytes (control frames) reported as a request unanswered")
	}

	m = newMeter()
	m.Down(record(200))
	m.Up(make([]byte, 300))
	m.mu.Lock()
	m.lastDownAt -= 3000 // the long poll's request went 2.5 s ago
	m.lastUpAt -= 2500
	m.mu.Unlock()
	m.Down(record(200))
	m.Up(make([]byte, 300))
	if m.askOnce(nowMs() + 5000) {
		t.Fatal("a request on a connection whose earlier answer took 2.5 s (a long poll's) reported")
	}
}
