package switchboard

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/tsyrenov1987/farvater-core/brain"
	"github.com/tsyrenov1987/farvater-core/catalogue"
	"github.com/tsyrenov1987/farvater-core/wire"
)

// gramWire carries datagrams as datagrams; ready says its connection is up.
type gramWire struct {
	streamWire
	ready atomic.Bool
}

func (w *gramWire) DatagramsReady() bool { return w.ready.Load() }
func (w *gramWire) DialPacket(context.Context) (wire.PacketSession, error) {
	return nil, errors.New("not dialled in this test")
}

// A UDP association goes first to a path that carries datagrams as datagrams
// while that path's connection is up; with it down the brain's order stands.
// Either way no path leaves the order.
func TestUDPGoesFirstToAReadyDatagramPath(t *testing.T) {
	cat, err := catalogue.Parse([]byte("vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?security=tls&sni=a.example.com&type=tcp#a\n" +
		"vless://00000000-0000-0000-0000-000000000000@127.0.0.2:1?security=tls&sni=b.example.com&type=tcp#b\n" +
		"vless://00000000-0000-0000-0000-000000000000@127.0.0.3:1?security=tls&sni=c.example.com&type=tcp#c"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(DefaultConfig(), cat)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.b.Pick(nowMs(), "x", brain.DstTLS443)
	s.mu.Unlock()
	before := s.udpOrder()
	last := before[len(before)-1]
	g := &gramWire{streamWire: streamWire{id: last, n: 1}}
	s.wires[last] = g

	if got := s.udpOrder(); got[0] != before[0] || len(got) != len(before) {
		t.Fatalf("a datagram path that is not up changed the order: %v, was %v", got, before)
	}
	g.ready.Store(true)
	got := s.udpOrder()
	if got[0] != last {
		t.Fatalf("order %v: the ready datagram path %s is not first", got, last)
	}
	if len(got) != len(before) || got[1] != before[0] {
		t.Fatalf("order %v, was %v: the other paths did not keep their place behind it", got, before)
	}
	s.mu.Lock()
	s.udpBack[last] = nowMs() + 60000
	s.mu.Unlock()
	if got := s.udpOrder(); got[len(got)-1] != last {
		t.Fatalf("order %v: a datagram path that refused UDP is not at the back", got)
	}
}
