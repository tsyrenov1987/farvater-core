package brain

import (
	"slices"
	"testing"
)

// A sleeping path (a hosted transport that is down) is out of the fan: never
// a flow's dial of any rank, not even when every awake path is tripped, and
// never tried for UDP. Awake again, the floor gives it a flow at once.
func TestAsleepPathIsNeverDialled(t *testing.T) {
	paths := []PathInfo{{ID: "A", SNI: "a", IP: "1", Rail: "reality"}, {ID: "B", SNI: "b", IP: "2", Rail: "xhttp"}, {ID: "O", Rail: "olcrtc", NotHTTP: true}}
	b := New(DefaultConfig(), "t", paths, 1)
	now := int64(1000)
	b.Sleep("O", now)
	if !b.Asleep("O") || b.Asleep("A") {
		t.Fatal("Asleep does not report the sleeping path")
	}
	for range 8 {
		now += 100
		b.Observe(deliv("O", now)) // even proven delivery does not wake it
	}
	b.Observe(reset("A", now))
	b.Observe(reset("B", now))
	for range 400 {
		now += 5_000 // past the floor many times over
		d := b.Pick(now, "h", DstTLS443)
		if d.Primary == "O" || d.Secondary == "O" || d.Tertiary == "O" {
			t.Fatalf("the sleeping path was dialled: %+v", d)
		}
	}
	if o := b.UDPOrder(now); slices.Contains(o, "O") || len(o) != 2 {
		t.Fatalf("UDP order %v, want A and B only", o)
	}
	b.Wake("O", now)
	if d := b.Pick(now+1, "h", DstTLS443); d.Primary != "O" || d.Reason != "explore_floor" {
		t.Fatalf("awake again, the next flow should explore it: %+v", d)
	}
	if o := b.UDPOrder(now + 1); !slices.Contains(o, "O") {
		t.Fatalf("awake, UDP order %v lacks it", o)
	}
}

// A leader that falls asleep is replaced at once, and with every path asleep
// a flow gets no path at all rather than one that cannot carry it.
func TestAsleepLeaderAndNoneAwake(t *testing.T) {
	paths := []PathInfo{{ID: "O", Rail: "olcrtc", NotHTTP: true}, {ID: "P", Rail: "olcrtc", NotHTTP: true}}
	b := New(DefaultConfig(), "t", paths, 1)
	if d := b.Pick(1000, "h", DstTLS443); d.Primary != "O" {
		t.Fatalf("leader %+v, want O", d)
	}
	b.Sleep("O", 1100)
	if d := b.Pick(1200, "h", DstTLS443); d.Primary != "P" || b.Leader() != "P" {
		t.Fatalf("O asleep: %+v, leader %q; want P", d, b.Leader())
	}
	b.Sleep("P", 1300)
	if d := b.Pick(1400, "h", DstTLS443); d.Primary != "" || d.Secondary != "" || d.Tertiary != "" {
		t.Fatalf("everything asleep, yet a dial: %+v", d)
	}
	if o := b.UDPOrder(1400); len(o) != 0 {
		t.Fatalf("everything asleep, UDP order %v", o)
	}
}
