package brain

import "testing"

// A leader dethroned for stalls has the longer record of delivery: the
// posterior rule must not hand the lead straight back to it.
func TestStalledLeaderIsNotReelectedAtOnce(t *testing.T) {
	paths := []PathInfo{{ID: "a", SNI: "a.ex", IP: "10.0.0.1"}, {ID: "b", SNI: "b.ex", IP: "10.0.0.2"}}
	br := New(DefaultConfig(), "t", paths, 7)
	now := int64(1000)
	good := func(p string) Receipt {
		return Receipt{Path: p, AtMs: now, WireReadyMs: 30, FirstByteMs: 50, Down: 100 * KB, End: EndRemoteFin, DownAtFail: -1}
	}
	for i := 0; i < 20; i++ { // a long good record on a
		now += 1000
		br.Pick(now, "x", DstTLS443)
		br.Observe(good("a"))
	}
	if br.Leader() != "a" {
		t.Fatalf("leader %q, want a", br.Leader())
	}
	for i := 0; i < 2; i++ { // then a freezes, a minute apart: too slow for the breaker's window
		now += 61_000
		br.Observe(Receipt{Path: "a", AtMs: now, WireReadyMs: 30, FirstByteMs: 50, Down: 16 * KB, DownAtFail: 16 * KB, Stalls: 1, End: EndLocalClose})
	}
	for i := 0; i < 30; i++ {
		now += 1000
		d := br.Pick(now, "x", DstTLS443)
		if br.Leader() == "a" && i > 0 {
			t.Fatalf("pick %d: the frozen a is leader again (%v)", i, br.J.Entries()[len(br.J.Entries())-1])
		}
		if d.Primary == "b" {
			br.Observe(good("b"))
		}
	}
}
