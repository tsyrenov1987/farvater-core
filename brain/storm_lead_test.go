package brain

import "testing"

// Two rails trip: a storm. A storm sends up to StormExplore of the flows to
// other paths, to find one that still delivers when the leader cannot be
// trusted. A leader that answers since it took the lead is that path already:
// the storm's probes would only carry the app's flows to paths that reset
// them (allow lists, resets after the first kilobytes), one after another.
// While no leader answers, the storm still explores wide.
func TestStormLeansOnALeaderThatAnswers(t *testing.T) {
	run := func(answers bool) float64 {
		var paths []PathInfo
		for i, id := range []string{"a", "b", "c", "d", "e", "f"} {
			paths = append(paths, PathInfo{ID: id, SNI: id + ".ex", IP: "10.0.0." + string(rune('1'+i))})
		}
		br := New(DefaultConfig(), "t", paths, 7)
		now := int64(1000)
		br.Pick(now, "x", DstTLS443)
		lead := br.Leader()
		n := 0
		for _, p := range paths {
			if p.ID == lead || n == 2 {
				continue
			}
			n++
			for i := 0; i < 2; i++ {
				now += 100
				if ok, sig := br.Breaker.NoteSig(p.ID, SigReset, now); ok {
					br.tripped(p.ID, sig, now)
				}
			}
		}
		if !br.Breaker.Storm(now) {
			t.Fatal("two tripped rails are no storm")
		}
		explored := 0
		for i := 0; i < 100; i++ {
			now += 200
			d := br.Pick(now, "x", DstTLS443)
			if d.Explore {
				explored++
			}
			if answers {
				r := ok(4 << 10)
				r.Path, r.AtMs, r.DurMs = lead, now, 100
				br.Observe(r)
			}
		}
		return float64(explored) / 100
	}
	if s := run(true); s > DefaultConfig().ExploreShare+0.02 {
		t.Fatalf("a storm took %.2f of the flows off a leader that answers, over the ordinary %.2f", s, DefaultConfig().ExploreShare)
	}
	if s := run(false); s < 0.3 {
		t.Fatalf("a storm with a leader that does not answer explored only %.2f of the flows", s)
	}
}
