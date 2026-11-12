package brain

import (
	"fmt"
	"testing"
)

// An app on the computer kept dialling addresses nobody answers (a dead proxy,
// peers long gone): through every path the wire connected and nothing came
// back, while the same paths answered the other flows at once. Two new
// addresses in a row cost a path two blackhole signals before the destination
// quarantine could see either; the path tripped, and the lead moved every 15 s
// across all 26 paths (Galzud, Windows 1.0.4, 12.11.2026).
func TestDeadDestinationsDoNotTripAnsweringPath(t *testing.T) {
	paths := []PathInfo{{ID: "a", SNI: "a.ex", IP: "10.0.0.1"}, {ID: "b", SNI: "b.ex", IP: "10.0.0.2"}}
	br := New(DefaultConfig(), "t", paths, 7)
	now := int64(1000)
	br.Pick(now, "x", DstTLS443)
	lead := br.Leader()
	for i := 0; i < 30; i++ {
		now += 2000
		br.Observe(Receipt{Path: lead, AtMs: now, WireReadyMs: 30, FirstByteMs: 80, Down: 64 * KB, DurMs: 300, End: EndRemoteFin, DownAtFail: -1, Dst: "youtube.com"})
		for k := 0; k < 2; k++ {
			at := now + int64(10+k)
			br.Observe(Receipt{Path: lead, AtMs: at, WireReadyMs: 30, FirstByteMs: -1, DurMs: 10_000, End: EndTimeout, DownAtFail: -1, Dst: fmt.Sprintf("149.154.%d.%d", i, k)})
			if br.Breaker.Tripped(lead, at) {
				t.Fatalf("dead destination %d.%d tripped the answering leader", i, k)
			}
		}
	}
	if br.Drops.Dst < 60 {
		t.Fatalf("dead-destination receipts left out: %d, want 60", br.Drops.Dst)
	}
}

// A path the TSPU blackholes answers nobody, new destinations included: its
// silence still counts and trips it.
func TestBlackholedPathStillTrips(t *testing.T) {
	paths := []PathInfo{{ID: "a", SNI: "a.ex", IP: "10.0.0.1"}, {ID: "b", SNI: "b.ex", IP: "10.0.0.2"}}
	br := New(DefaultConfig(), "t", paths, 7)
	now := int64(1000)
	br.Pick(now, "x", DstTLS443)
	lead := br.Leader()
	for i := 0; i < 5; i++ {
		now += 1000
		br.Observe(Receipt{Path: lead, AtMs: now, WireReadyMs: 30, FirstByteMs: 80, Down: 64 * KB, DurMs: 300, End: EndRemoteFin, DownAtFail: -1, Dst: "youtube.com"})
	}
	const dur = 10_000
	now += DeadDstAnswerMs + dur + 1000 // the path went silent
	for i := 0; i < 3; i++ {
		now += 1000
		br.Observe(Receipt{Path: lead, AtMs: now, WireReadyMs: 30, FirstByteMs: -1, DurMs: dur, End: EndTimeout, DownAtFail: -1, Dst: fmt.Sprintf("new%d.example", i)})
	}
	if !br.Breaker.Tripped(lead, now) {
		t.Fatal("a path that answers nobody must trip")
	}
}
