package brain

import "testing"

// When the breaker has tripped every path, all of them stay available, but the
// leader is the one whose cooldown ends first, not the one with the best
// history that tripped a moment ago.
func TestAllTrippedLeadsWithTheEarliestTrip(t *testing.T) {
	paths := []PathInfo{{ID: "a", SNI: "a.ex", IP: "10.0.0.1"}, {ID: "b", SNI: "b.ex", IP: "10.0.0.2"},
		{ID: "c", SNI: "c.ex", IP: "10.0.0.3"}}
	br := New(DefaultConfig(), "t", paths, 7)
	now := int64(1000)
	br.Pick(now, "x", DstTLS443)
	lead := br.Leader()
	// the leader's long record of delivery
	for i := 0; i < 20; i++ {
		now += 100
		br.Observe(Receipt{Path: lead, AtMs: now, WireReadyMs: 30, FirstByteMs: 80, Down: 64 << 10, DurMs: 200, End: EndRemoteFin, DownAtFail: -1})
	}
	trip := func(p string) {
		for i := 0; i < 2; i++ {
			if ok, sig := br.Breaker.NoteSig(p, SigHandshake, now); ok {
				br.tripped(p, sig, now)
			}
		}
	}
	var first string
	for _, p := range paths {
		if p.ID != lead {
			now += 1000
			trip(p.ID)
			if first == "" {
				first = p.ID
			}
		}
	}
	now += 1000
	trip(lead)
	for i := 0; i < 5; i++ {
		now += 100
		br.Pick(now, "x", DstTLS443)
		if br.Leader() != first {
			t.Fatalf("pick %d with every path tripped: leader %q, want %s, tripped first (%v)", i, br.Leader(), first, br.J.Entries()[len(br.J.Entries())-1])
		}
	}
}
