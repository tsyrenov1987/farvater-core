package switchboard

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/catalogue"
)

// A path that swallows uploads takes the app's bytes and gives nothing back,
// at a record boundary, so the stall watchdog sees nothing. Waiting for those
// flows to end means waiting for the app's own timeout, half a minute, before
// the breaker hears of it. Flows that sent swallowedBytes, stopped and got no
// answer for UnansweredMs count as stalled while still open, and two of them
// condemn the path. An upload still going out does not, nor a small request a
// messenger's long poll leaves waiting on a healthy path.
func TestSwallowedUploadsCondemnThePath(t *testing.T) {
	cat, err := catalogue.Parse([]byte("vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?security=tls&sni=a.example.com&type=tcp#a"))
	if err != nil {
		t.Fatal(err)
	}
	run := func(sent int, uploading bool) bool {
		s, err := New(DefaultConfig(), cat)
		if err != nil {
			t.Fatal(err)
		}
		id := s.Paths()[0]
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		defer wg.Wait()
		defer cancel()
		var as []*attempt
		for i := 0; i < 2; i++ {
			f := &flow{s: s, fbDeadlineMs: 300, up: make(chan []byte)}
			a := f.newAttempt(id, false)
			as = append(as, a)
			wg.Go(func() { f.run(ctx, answeredOnce{}, a, nil) })
		}
		time.Sleep(100 * time.Millisecond)
		for _, a := range as {
			a.m.Up(make([]byte, sent)) // the app sends on the answered connection
		}
		up := time.NewTicker(500 * time.Millisecond)
		defer up.Stop()
		for end := time.Now().Add(11 * time.Second); time.Now().Before(end); {
			<-up.C
			if s.tripped(id, nowMs()) {
				return true
			}
			if uploading {
				for _, a := range as {
					a.m.Up(make([]byte, 2000))
				}
			}
		}
		return false
	}
	if !run(64<<10, false) {
		t.Fatal("two open flows sent 64 KB and got nothing back for 11 s: the path is not condemned")
	}
	if run(64<<10, true) {
		t.Fatal("two flows still uploading condemned their path")
	}
	if run(2000, false) {
		t.Fatal("two long-poll requests waiting for their answer condemned the path")
	}
}
