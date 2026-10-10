package switchboard

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/catalogue"
	"github.com/tsyrenov1987/farvater-core/wire"
)

// sharedWire carries every flow over one shared connection, the way the gRPC
// and XHTTP wires ride their streams on one HTTP/2 connection. Once that
// connection dies in silence (a NAT that forgot it, a network the phone left),
// every flow over it is ready at once and never answered, until Refresh makes
// the next flow dial a fresh connection.
type sharedWire struct {
	id   string
	dead atomic.Bool
}

func (w *sharedWire) ID() string           { return w.id }
func (w *sharedWire) Spec() wire.PathSpec  { return wire.PathSpec{ID: w.id} }
func (w *sharedWire) NeedsHandshake() bool { return false }
func (w *sharedWire) Close() error         { return nil }
func (w *sharedWire) Refresh(time.Time)    { w.dead.Store(false) }
func (w *sharedWire) Dial(context.Context) (wire.Session, error) {
	if w.dead.Load() {
		return silent{}, nil
	}
	return streamSession{100}, nil
}

// sharedBoard is a switchboard over one path, "a", carried by a sharedWire.
func sharedBoard(t *testing.T) (*Switchboard, string, *sharedWire) {
	t.Helper()
	cat, err := catalogue.Parse([]byte("vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?security=tls&sni=a.example.com&type=grpc#a"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(DefaultConfig(), cat)
	if err != nil {
		t.Fatal(err)
	}
	s.probe = func(context.Context, []string) bool { return false }
	for i := 0; i < 6; i++ {
		s.observe(delivered("a")) // quick first bytes: a short first-byte deadline
	}
	w := &sharedWire{id: "a"}
	s.wires["a"] = w
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.serveListener(ctx, ln) }()
	return s, ln.Addr().String(), w
}

// answered opens a flow, asks, and reports whether anything came back.
func answered(t *testing.T, addr string) bool {
	t.Helper()
	c, rep := socksTo(t, addr, "example.com", 443)
	if rep != 0 {
		t.Fatalf("socks reply %d", rep)
	}
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := c.Write(record(300)); err != nil {
		t.Fatal(err)
	}
	n, _ := io.ReadFull(c, make([]byte, 100))
	return n == 100
}

// A flow that gets no answer on a shared connection leaves it behind: the next
// flow over the path dials a fresh one instead of dying on the same dead
// connection until the system gives up on it (minutes).
func TestUnansweredFlowRefreshesASharedConnection(t *testing.T) {
	_, addr, w := sharedBoard(t)
	if !answered(t, addr) {
		t.Fatal("setup: the live connection did not answer")
	}
	w.dead.Store(true)
	if answered(t, addr) {
		t.Fatal("setup: the dead connection answered")
	}
	if !answered(t, addr) {
		t.Fatal("the next flow rode the dead connection again")
	}
}

// A network change leaves every shared connection behind: they were made on
// the network the phone left, so the first flow on the new one dials afresh.
func TestNetworkChangeRefreshesSharedConnections(t *testing.T) {
	s, addr, w := sharedBoard(t)
	if !answered(t, addr) {
		t.Fatal("setup: the live connection did not answer")
	}
	w.dead.Store(true)
	s.SetNetwork("cell")
	if !answered(t, addr) {
		t.Fatal("the first flow after the network change rode the old network's connection")
	}
}
