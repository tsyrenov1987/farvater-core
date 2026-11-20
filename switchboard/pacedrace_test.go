package switchboard

import (
	"context"
	"sync"
	"testing"

	"github.com/tsyrenov1987/farvater-core/brain"
	"github.com/tsyrenov1987/farvater-core/catalogue"
)

// shakeWire handshakes per flow (raw TCP, WebSocket) and its dials come up at once.
type shakeWire struct{ streamWire }

func (w *shakeWire) NeedsHandshake() bool { return true }

// A page opens a burst of connections on a leader that handshakes per flow:
// the governor queues the handshakes, the stagger brings the runner-up in for
// the ones that waited. The leader's dial never went out: it lost nothing, and
// the wait is the core's own, not a leader whose dials hang.
func TestAHandshakeQueuedByTheGovernorIsNotALostRace(t *testing.T) {
	cat, err := catalogue.Parse([]byte("vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?security=tls&sni=a.example.com&type=tcp#a\n" +
		"vless://00000000-0000-0000-0000-000000000000@127.0.0.2:1?security=tls&sni=b.example.com&type=tcp#b"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(DefaultConfig(), cat)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.b.Pick(nowMs(), "x", brain.DstTLS443)
	lead := s.b.Leader()
	s.mu.Unlock()
	other := s.Paths()[0]
	if other == lead {
		other = s.Paths()[1]
	}
	s.wires[lead] = &shakeWire{streamWire{id: lead, n: 100}}
	s.wires[other] = &streamWire{id: other, n: 100}
	var wg sync.WaitGroup
	var mu sync.Mutex
	rescued := 0
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f := &flow{s: s}
			sess, a, err := f.dialRace(context.Background(), []string{lead, other}, 300, false)
			if err != nil {
				t.Error(err)
				return
			}
			if a.path == other {
				mu.Lock()
				rescued++
				mu.Unlock()
			}
			sess.Close()
		}()
	}
	wg.Wait()
	t.Logf("%d of 12 flows went to the runner-up while the leader's handshake waited its turn", rescued)
	if st := s.Status(); st.Paced == 0 || st.PacedMs < st.PacedMax || st.PacedMax < 250 {
		t.Fatalf("status counts %d queued handshakes, %d ms in all, %d ms the longest: the burst's wait is not told", st.Paced, st.PacedMs, st.PacedMax)
	} else {
		t.Logf("status: %d handshakes queued, %d ms in all, %d ms the longest", st.Paced, st.PacedMs, st.PacedMax)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.b.J.Entries() {
		if e.Act == "lead_race" {
			t.Fatalf("the leader is in doubt (%s) for handshakes the core itself queued", e.Why)
		}
	}
}
