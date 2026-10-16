package brain

import (
	"slices"
	"testing"
)

// The leader delivers fast; the other paths are measured shaped but one, not
// measured yet. Exploration goes to that one only: a flow sent to explore a
// path known shaped learns nothing new, and the user waits on it (a reel that
// hangs for a quarter of a minute).
func TestExploreSkipsAPathKnownShaped(t *testing.T) {
	paths := sweepPaths()
	br := New(DefaultConfig(), "t", paths, 7)
	now := warm(br, paths, 1000)
	br.Pick(now, "x", DstTLS443)
	lead := br.Leader()
	unmeasured := ""
	for _, p := range paths {
		switch {
		case p.ID == lead:
		case unmeasured == "":
			unmeasured = p.ID
		default:
			br.NoteGoodput(p.ID, 256<<10, 17000, now-17000, now) // 15 KB/s
		}
	}
	for i := 0; i < 2; i++ {
		br.NoteGoodput(lead, 256<<10, 100, now-100, now)
	}
	explored := map[string]int{}
	for i := 0; i < 300; i++ {
		now += 200
		br.NoteAnswered(lead, now-50, now)
		if d := br.Pick(now, "x", DstTLS443); d.Primary != lead {
			explored[d.Primary]++
		}
	}
	if br.Leader() != lead {
		t.Fatalf("leader moved %s → %s", lead, br.Leader())
	}
	for p, n := range explored {
		if p != unmeasured {
			t.Fatalf("%d flows explored %s, measured at 15 KB/s, with the leader fast (all: %v)", n, p, explored)
		}
	}
	if explored[unmeasured] == 0 {
		t.Fatalf("no flow explored %s, not measured yet: exploration is gone", unmeasured)
	}
}

// While a sweep's probes are out, flows do not explore the paths they
// measure: such a flow waits behind the probe on a shaped path and learns
// nothing the probe does not.
func TestNoExploreOntoAPathUnderProbe(t *testing.T) {
	paths := sweepPaths()
	br := New(DefaultConfig(), "t", paths, 7)
	now := int64(1000)
	br.Pick(now, "x", DstTLS443)
	lead := br.Leader()
	for i := 0; i < 20; i++ {
		for _, p := range paths {
			now += 50
			r := ok(8 << 10)
			r.Path, r.AtMs, r.DurMs = p.ID, now, 100
			if p.ID == lead {
				r.AnswerMs = 900
			}
			br.Observe(r)
		}
	}
	probed := br.SweepDue(now)
	if len(probed) < 2 {
		t.Fatalf("no sweep of a leader that answers in 900 ms: %v", probed)
	}
	for i := 0; i < 50; i++ {
		now += 20
		d := br.Pick(now, "x", DstTLS443)
		if d.Primary != br.Leader() && slices.Contains(probed, d.Primary) {
			t.Fatalf("flow %d explored %s (%s) while its probe is out", i, d.Primary, d.Reason)
		}
	}
}

// The leader delivers fast; the other paths are measured shaped. The app goes
// quiet for a minute (a reel plays, or two downloads take every connection),
// then opens a few flows at once. A leader that heard nothing because nobody
// asked it is no leader in doubt: those flows stay off the shaped paths. In
// the lab every such pause sent the next 1 MB download to a path measured at
// 16 KB/s, and it took 65 s.
func TestExploreAfterAQuietMinuteSkipsAPathKnownShaped(t *testing.T) {
	paths := sweepPaths()
	br := New(DefaultConfig(), "t", paths, 7)
	now := warm(br, paths, 1000)
	br.Pick(now, "x", DstTLS443)
	lead := br.Leader()
	for _, p := range paths {
		if p.ID != lead {
			br.NoteGoodput(p.ID, 256<<10, 17000, now-17000, now) // 15 KB/s
		}
	}
	for i := 0; i < 2; i++ {
		br.NoteGoodput(lead, 256<<10, 100, now-100, now)
	}
	shaped := map[string]int{}
	for pause := 0; pause < 8; pause++ {
		now += 60_000
		for i := 0; i < 3; i++ {
			now += 5
			if d := br.Pick(now, "x", DstTLS443); d.Primary != lead {
				shaped[d.Primary]++
			}
		}
		now += 50
		br.NoteAnswered(lead, now-50, now)
	}
	if br.Leader() != lead {
		t.Fatalf("leader moved %s → %s", lead, br.Leader())
	}
	if len(shaped) > 0 {
		t.Fatalf("after a quiet minute flows went to paths measured at 15 KB/s, with the leader fast: %v", shaped)
	}
	// A leader asked in vain is in doubt: a shaped path that still delivers
	// is worth a try again.
	for i := 0; i < 100; i++ {
		now += 200
		if d := br.Pick(now, "x", DstTLS443); d.Primary != lead {
			shaped[d.Primary]++
		}
	}
	if len(shaped) == 0 {
		t.Fatal("a leader silent for 20 s kept every flow off the other paths")
	}
}
