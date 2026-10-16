package switchboard

import (
	"context"
	"testing"

	"github.com/tsyrenov1987/farvater-core/brain"
	"github.com/tsyrenov1987/farvater-core/catalogue"
	"github.com/tsyrenov1987/farvater-core/wire"
)

// hangWire's dials never come up (an allow list drops the handshake).
type hangWire struct{ id string }

func (w *hangWire) ID() string           { return w.id }
func (w *hangWire) Spec() wire.PathSpec  { return wire.PathSpec{ID: w.id} }
func (w *hangWire) NeedsHandshake() bool { return false }
func (w *hangWire) Close() error         { return nil }
func (w *hangWire) Dial(ctx context.Context) (wire.Session, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// The leader's dial hangs and the runner-up's comes up after the stagger: the
// flow is rescued and files nothing against the leader. The race it lost goes
// to the brain, and two of them in a row put the leader in doubt (brain.NoteRace).
func TestALeaderThatLosesTheConnectRaceIsInDoubt(t *testing.T) {
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
	s.wires[lead] = &hangWire{id: lead}
	s.wires[other] = &streamWire{id: other, n: 100}
	for i := 0; i < 2; i++ {
		f := &flow{s: s}
		sess, a, err := f.dialRace(context.Background(), []string{lead, other}, 30, false)
		if err != nil || a.path != other {
			t.Fatalf("race %d: %v over %v, want the runner-up %s", i, err, a, other)
		}
		sess.Close()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.b.SweepDue(nowMs()); len(p) == 0 || p[0] != lead {
		t.Fatalf("swept %v after the leader %s lost two connect races in a row, want it probed first", p, lead)
	}
}
