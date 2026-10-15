package switchboard

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/catalogue"
	"github.com/tsyrenov1987/farvater-core/wire"
)

// frozenSession answers 300 bytes of a 1000-byte TLS record and then holds
// the connection open in silence, as a TSPU box freezing a flow does. With
// whole, the site's record arrives whole and only the path's own record is
// cut: the freeze shows on the path's stream alone.
type frozenSession struct{ whole bool }

func (s frozenSession) InRecord() bool { return s.whole }

func (s frozenSession) Run(ctx context.Context, _ wire.Target, _ []byte, _ <-chan []byte, down io.Writer, m wire.Meter) (wire.Outcome, error) {
	p := record(1000)[:300]
	if s.whole {
		p = record(295)
	}
	m.Down(p)
	if _, err := down.Write(p); err != nil {
		return wire.OutcomeError, err
	}
	<-ctx.Done()
	return wire.OutcomeCanceled, ctx.Err()
}
func (frozenSession) Close() error { return nil }

type frozenWire struct {
	id    string
	whole bool
}

func (w frozenWire) ID() string                                 { return w.id }
func (w frozenWire) Spec() wire.PathSpec                        { return wire.PathSpec{ID: w.id} }
func (w frozenWire) NeedsHandshake() bool                       { return false }
func (w frozenWire) Close() error                               { return nil }
func (w frozenWire) Refresh(time.Time)                          {}
func (w frozenWire) Dial(context.Context) (wire.Session, error) { return frozenSession{w.whole}, nil }

// The app waits on a frozen flow until its own timeout, half a minute on
// many; the flows it opens meanwhile must not go to the frozen leader. So the
// leader goes once its flows stall, while they are still open.
func TestStalledFlowsDethroneTheLeaderWhileOpen(t *testing.T) {
	t.Run("site record cut", func(t *testing.T) { dethroneWhileFrozen(t, false) })
	t.Run("path record cut", func(t *testing.T) { dethroneWhileFrozen(t, true) })
}

func dethroneWhileFrozen(t *testing.T, whole bool) {
	cat, err := catalogue.Parse([]byte("vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?security=tls&sni=a.example.com&type=tcp#a\n" +
		"vless://00000000-0000-0000-0000-000000000000@127.0.0.2:1?security=tls&sni=b.example.com&type=tcp#b"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.StallMs = 300
	s, err := New(cfg, cat)
	if err != nil {
		t.Fatal(err)
	}
	s.probe = func(context.Context, []string) bool { return false }
	ids := []string{}
	for id := range s.wires {
		ids = append(ids, id)
	}
	for i := 0; i < 6; i++ {
		for _, id := range ids {
			s.observe(delivered(id))
		}
	}
	victim := leaderOf(s)
	for _, id := range ids {
		s.wires[id] = frozenWire{id, whole}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.serveListener(ctx, ln) }()
	// the app keeps opening flows; some go to other paths to explore, the
	// rest freeze on the leader
	dethroned := func() bool {
		if l := leaderOf(s); l != victim && l != "" {
			if len(s.Receipts()) != 6*len(ids) {
				t.Fatalf("the frozen flows ended before the hand-over")
			}
			return true
		}
		return false
	}
	for i := 0; i < 6; i++ {
		c, rep := socksTo(t, ln.Addr().String(), "example.com", 443)
		if rep != 0 {
			t.Fatalf("socks reply %d", rep)
		}
		if _, err := c.Write(record(300)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(c, make([]byte, 300)); err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Time{}) // the app keeps waiting
		if i >= 1 {
			for end := time.Now().Add(700 * time.Millisecond); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
				if dethroned() {
					return
				}
			}
		}
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if dethroned() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("leader still %s 4 s into six frozen flows (journal %v)", victim, s.b.J.Entries())
}
