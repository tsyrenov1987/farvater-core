package switchboard

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/catalogue"
	"github.com/tsyrenov1987/farvater-core/wire"
)

// oldNetWire's first dial went out on a network that is gone and hangs; the
// ones after it come up.
type oldNetWire struct {
	id    string
	dials atomic.Int32
}

func (w *oldNetWire) ID() string           { return w.id }
func (w *oldNetWire) Spec() wire.PathSpec  { return wire.PathSpec{ID: w.id} }
func (w *oldNetWire) NeedsHandshake() bool { return false }
func (w *oldNetWire) Close() error         { return nil }
func (w *oldNetWire) Dial(ctx context.Context) (wire.Session, error) {
	if w.dials.Add(1) == 1 {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return streamSession{100}, nil
}

// The device changes network while a flow dials: the dial is not left to
// hang out its timeout, it is made again at once on the new network.
func TestADialLeftOnTheOldNetworkIsMadeAgainAtOnce(t *testing.T) {
	cat, err := catalogue.Parse([]byte("vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?security=tls&sni=a.example.com&type=tcp#a"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Ctx = "wifi"
	s, err := New(cfg, cat)
	if err != nil {
		t.Fatal(err)
	}
	id := s.Paths()[0]
	w := &oldNetWire{id: id}
	s.wires[id] = w
	go func() {
		time.Sleep(100 * time.Millisecond)
		s.SetNetwork("cell")
	}()
	start := time.Now()
	f := &flow{s: s}
	sess, err := f.dialOne(context.Background(), f.newAttempt(id, false))
	if err != nil {
		t.Fatal(err)
	}
	sess.Close()
	if d := time.Since(start); d > time.Second {
		t.Fatalf("the flow connected after %v: it waited out the dial on the old network", d)
	}
	if n := w.dials.Load(); n != 2 {
		t.Fatalf("%d dials, want the hung one and one more", n)
	}
}
