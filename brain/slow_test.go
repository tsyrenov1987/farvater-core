package brain

import "testing"

// bulk is a 1 MB download that took busyMs of flowing time.
func bulk(path string, at, busyMs int64) Receipt {
	return Receipt{Path: path, AtMs: at, WireReadyMs: 30, FirstByteMs: 80, Down: 1 << 20, BusyDown: 1 << 20, BusyMs: busyMs,
		DurMs: 80 + busyMs, End: EndRemoteFin, DownAtFail: -1}
}

// A leader that delivers everything at 16 KB/s gives no stall, no reset and no
// timeout: only its goodput tells it apart from a path at 10 MB/s.
func TestSlowLeaderHandsOverToAFasterPath(t *testing.T) {
	paths := []PathInfo{{ID: "a", SNI: "a.ex", IP: "10.0.0.1"}, {ID: "b", SNI: "b.ex", IP: "10.0.0.2"},
		{ID: "c", SNI: "c.ex", IP: "10.0.0.3"}, {ID: "d", SNI: "d.ex", IP: "10.0.0.4"}}
	busy := map[string]int64{"a": 64_000, "b": 64_000, "c": 100, "d": 64_000} // only c is fast
	br := New(DefaultConfig(), "t", paths, 7)
	now := int64(1000)
	br.Pick(now, "x", DstTLS443)
	if br.Leader() != "a" {
		t.Fatalf("first leader %q, want a", br.Leader())
	}
	probes := 0
	for i := 0; i < 60 && br.Leader() != "c"; i++ {
		now += 5000
		d := br.Pick(now, "x", DstTLS443)
		if d.Reason == "speed_probe" {
			probes++
		}
		br.Observe(bulk(d.Primary, now+busy[d.Primary], busy[d.Primary]))
	}
	if br.Leader() != "c" {
		t.Fatalf("leader %q after 60 downloads, want the fast c (speed probes %d)", br.Leader(), probes)
	}
	if br.J.Count("lead_slow") != 1 {
		t.Fatalf("lead_slow %d times, want 1", br.J.Count("lead_slow"))
	}
	t.Logf("c took the lead after %d speed probes", probes)
	// ...and keeps it: the slow paths' long record of delivery does not win it back.
	for i := 0; i < 60; i++ {
		now += 5000
		d := br.Pick(now, "x", DstTLS443)
		br.Observe(bulk(d.Primary, now+busy[d.Primary], busy[d.Primary]))
		if br.Leader() != "c" {
			t.Fatalf("download %d after the hand-over: leader back to %q (%v)", i, br.Leader(), br.J.Entries()[len(br.J.Entries())-1])
		}
	}
}

// A fast leader is never probed for speed, and a keep-alive connection that
// spent minutes idle between quick answers is not slow.
func TestFastOrIdleLeaderIsNotProbedForSpeed(t *testing.T) {
	paths := []PathInfo{{ID: "a", SNI: "a.ex", IP: "10.0.0.1"}, {ID: "b", SNI: "b.ex", IP: "10.0.0.2"}}
	br := New(DefaultConfig(), "t", paths, 7)
	now := int64(1000)
	for i := 0; i < 40; i++ {
		now += 5000
		d := br.Pick(now, "x", DstTLS443)
		if d.Reason == "speed_probe" {
			t.Fatalf("speed probe at pick %d with a fast leader", i)
		}
		r := bulk(d.Primary, now, 200)
		r.DurMs = 10 * 60_000 // open ten minutes, busy 200 ms
		br.Observe(r)
	}
	if bps, n, _ := br.State("a").Goodput(now, 60_000); n == 0 || bps < 1<<20 {
		t.Fatalf("idle keep-alive goodput %.0f B/s over %d samples, want the busy rate (≈5 MB/s)", bps, n)
	}
}

// On a slow network every path is slow: once SpeedProbeMax of them are
// measured, speed probes take no more flows than ordinary exploration does,
// and the leader stays.
func TestSlowNetworkStopsSpeedProbes(t *testing.T) {
	var paths []PathInfo
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		paths = append(paths, PathInfo{ID: id, SNI: id + ".ex", IP: "10.0.0." + id})
	}
	cfg := DefaultConfig()
	br := New(cfg, "t", paths, 7)
	now := int64(1000)
	probes, late, lateExplore := 0, 0, 0
	for i := 0; i < 120; i++ {
		now += 5000
		d := br.Pick(now, "x", DstTLS443)
		if d.Reason == "speed_probe" {
			probes++
			if i >= 60 {
				late++
			}
		}
		if i >= 60 && d.Primary != br.Leader() {
			lateExplore++
		}
		br.Observe(bulk(d.Primary, now+64_000, 64_000))
	}
	if probes > len(paths)-1 {
		t.Fatalf("%d speed probes among %d other paths", probes, len(paths)-1)
	}
	if share := float64(lateExplore) / 60; share > cfg.ExploreShare+0.05 {
		t.Fatalf("second half: %.2f of flows off the leader (%d speed probes), want ≤ ExploreShare %.2f", share, late, cfg.ExploreShare)
	}
	if br.J.Count("lead_slow") != 0 {
		t.Fatalf("leader handed over %d times among equally slow paths", br.J.Count("lead_slow"))
	}
}

// A censor that shapes all paths but one: the fast one is found however late
// the probes come to it, after SpeedProbeMax slow ones as well, and well
// before the slow ones' goodput goes stale (GoodputFreshMs, 120 downloads here).
func TestFastPathFoundAfterTheProbeLimit(t *testing.T) {
	ids := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	var paths []PathInfo
	for _, id := range ids {
		paths = append(paths, PathInfo{ID: id, SNI: id + ".ex", IP: "10.0.0." + id})
	}
	for seed := uint64(1); seed <= 30; seed++ {
		br := New(DefaultConfig(), "t", paths, seed)
		now := int64(1000)
		br.Pick(now, "x", DstTLS443)
		fast := ids[len(ids)-1]
		if br.Leader() == fast {
			fast = ids[0]
		}
		i := 0
		for ; i < 60 && br.Leader() != fast; i++ {
			now += 5000
			d := br.Pick(now, "x", DstTLS443)
			busy := int64(64_000)
			if d.Primary == fast {
				busy = 100
			}
			br.Observe(bulk(d.Primary, now+busy, busy))
		}
		if br.Leader() != fast {
			t.Fatalf("seed %d: leader %q after %d downloads, the only fast path %s never took over", seed, br.Leader(), i, fast)
		}
	}
}

// On a slow leader each download takes a minute and new flows are rare: a
// path measured faster takes the lead the moment its goodput comes, not at
// the next flow.
func TestFasterPathTakesTheLeadWithoutWaitingForAFlow(t *testing.T) {
	paths := []PathInfo{{ID: "a", SNI: "a.ex", IP: "10.0.0.1"}, {ID: "b", SNI: "b.ex", IP: "10.0.0.2"}}
	br := New(DefaultConfig(), "t", paths, 7)
	now := int64(1000)
	br.Pick(now, "x", DstTLS443)
	slow := br.Leader()
	fast := "a"
	if slow == "a" {
		fast = "b"
	}
	for i := 0; i < 2; i++ {
		now += 5000
		br.NoteGoodput(slow, 1<<20, 64_000, now-64_000, now)
	}
	now += 1000
	br.NoteGoodput(fast, 1<<20, 100, now-100, now)
	if br.Leader() != fast {
		t.Fatalf("leader %q right after %s was measured 640× faster, want %s", br.Leader(), fast, fast)
	}
	// ...and from a receipt alone, for a download too short to be noted live
	br = New(DefaultConfig(), "t", paths, 7)
	br.Pick(1000, "x", DstTLS443)
	for i := 0; i < 2; i++ {
		br.NoteGoodput(slow, 1<<20, 64_000, 1000, 70_000+int64(i))
	}
	br.Observe(bulk(fast, 71_000, 100))
	if br.Leader() != fast {
		t.Fatalf("leader %q right after a fast receipt from %s, want %s", br.Leader(), fast, fast)
	}
}
