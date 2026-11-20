package switchboard

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/catalogue"
	"github.com/tsyrenov1987/farvater-core/wire"
)

// busyWire shares a connection and is dialling it on the network left behind:
// its Refresh waits for the dial, as a wire's does.
type busyWire struct {
	id        string
	refreshed *atomic.Int32
}

func (w *busyWire) ID() string           { return w.id }
func (w *busyWire) Spec() wire.PathSpec  { return wire.PathSpec{ID: w.id} }
func (w *busyWire) NeedsHandshake() bool { return false }
func (w *busyWire) Close() error         { return nil }
func (w *busyWire) Refresh(time.Time) {
	time.Sleep(300 * time.Millisecond)
	w.refreshed.Add(1)
}
func (w *busyWire) Dial(context.Context) (wire.Session, error) { return streamSession{100}, nil }

// The device changes network while several paths dial: the call returns at
// once and every path is refreshed within one dial's wait, not their sum.
func TestANetworkChangeDoesNotWaitOutEveryPathsDial(t *testing.T) {
	cat, err := catalogue.Parse([]byte("vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?security=tls&sni=a.example.com&type=grpc#a\n" +
		"vless://00000000-0000-0000-0000-000000000000@127.0.0.2:1?security=tls&sni=b.example.com&type=grpc#b\n" +
		"vless://00000000-0000-0000-0000-000000000000@127.0.0.3:1?security=tls&sni=c.example.com&type=grpc#c\n" +
		"vless://00000000-0000-0000-0000-000000000000@127.0.0.4:1?security=tls&sni=d.example.com&type=grpc#d"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Ctx = "wifi"
	s, err := New(cfg, cat)
	if err != nil {
		t.Fatal(err)
	}
	var refreshed atomic.Int32
	for _, id := range s.Paths() {
		s.wires[id] = &busyWire{id: id, refreshed: &refreshed}
	}
	start := time.Now()
	s.SetNetwork("cell")
	if d := time.Since(start); d > 150*time.Millisecond {
		t.Fatalf("SetNetwork took %v with 4 paths dialling", d)
	}
	time.Sleep(500 * time.Millisecond)
	if n := refreshed.Load(); n != 4 {
		t.Fatalf("%d of 4 paths refreshed 500 ms after the change", n)
	}
}
