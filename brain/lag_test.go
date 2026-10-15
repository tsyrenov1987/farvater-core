package brain

import "testing"

// page is a 24 KB answer that came ansMs after the dial.
func page(path string, at, ansMs int64) Receipt {
	return Receipt{Path: path, AtMs: at, WireReadyMs: 30, FirstByteMs: ansMs + 10, AnswerMs: ansMs, Down: 24 << 10,
		DurMs: ansMs + 50, End: EndRemoteFin, DownAtFail: -1}
}

func lagPaths() []PathInfo {
	var paths []PathInfo
	for _, id := range []string{"a", "b", "c", "d", "e", "f"} {
		paths = append(paths, PathInfo{ID: id, SNI: id + ".ex", IP: "10.0.0." + id})
	}
	return paths
}

// A leader that delivers everything but answers 900 ms late (long round
// trips) gives no stall and no failure: only its answer time tells it apart
// from paths answering in 60 ms.
func TestLaggyLeaderHandsOverToAQuickerPath(t *testing.T) {
	ans := map[string]int64{"a": 900, "b": 900, "c": 900, "d": 60, "e": 60, "f": 60}
	for seed := uint64(1); seed <= 20; seed++ {
		br := New(DefaultConfig(), "t", lagPaths(), seed)
		now := int64(1000)
		br.Pick(now, "x", DstTLS443)
		if ans[br.Leader()] != 900 {
			continue // the test wants a late leader to start with
		}
		i := 0
		for ; i < 80 && ans[br.Leader()] == 900; i++ {
			now += 2000
			d := br.Pick(now, "x", DstTLS443)
			br.Observe(page(d.Primary, now+ans[d.Primary], ans[d.Primary]))
		}
		if ans[br.Leader()] != 60 {
			t.Fatalf("seed %d: leader %q answers in %d ms after %d pages", seed, br.Leader(), ans[br.Leader()], i)
		}
		if br.J.Count("lead_lag") != 1 {
			t.Fatalf("seed %d: lead_lag %d times, want 1", seed, br.J.Count("lead_lag"))
		}
		for k := 0; k < 80; k++ {
			now += 2000
			d := br.Pick(now, "x", DstTLS443)
			br.Observe(page(d.Primary, now+ans[d.Primary], ans[d.Primary]))
			if ans[br.Leader()] != 60 {
				t.Fatalf("seed %d, page %d after the hand-over: leader back to the late %q", seed, k, br.Leader())
			}
		}
	}
}

// Where every path answers late (a slow mobile network), the leader stays
// and probes take no more flows than ordinary exploration once
// SpeedProbeMax paths are measured.
func TestLaggyNetworkKeepsTheLeader(t *testing.T) {
	cfg := DefaultConfig()
	br := New(cfg, "t", lagPaths(), 7)
	now := int64(1000)
	off := 0
	for i := 0; i < 160; i++ {
		now += 2000
		d := br.Pick(now, "x", DstTLS443)
		if i >= 80 && d.Primary != br.Leader() {
			off++
		}
		br.Observe(page(d.Primary, now+900, 900+int64(i%7)*10))
	}
	if n := br.J.Count("lead_lag"); n != 0 {
		t.Fatalf("lead_lag %d times among equally late paths", n)
	}
	if share := float64(off) / 80; share > cfg.ExploreShare+0.05 {
		t.Fatalf("second half: %.2f of flows off the leader, want ≤ ExploreShare %.2f", share, cfg.ExploreShare)
	}
}

// A leader that answers quickly sends no flow to a lag probe.
func TestQuickLeaderIsNotProbedForLag(t *testing.T) {
	br := New(DefaultConfig(), "t", lagPaths(), 7)
	now := int64(1000)
	for i := 0; i < 80; i++ {
		now += 2000
		d := br.Pick(now, "x", DstTLS443)
		if d.Reason == "lag_probe" {
			t.Fatalf("lag probe at pick %d with a quick leader", i)
		}
		br.Observe(page(d.Primary, now+60, 60))
	}
}

// A path that answers soon but is shaped to 16 KB/s does not take the lead
// from a fast one that answers late: its downloads would crawl.
func TestQuickButShapedPathDoesNotTakeTheLead(t *testing.T) {
	paths := []PathInfo{{ID: "a", SNI: "a.ex", IP: "10.0.0.1"}, {ID: "b", SNI: "b.ex", IP: "10.0.0.2"}}
	br := New(DefaultConfig(), "t", paths, 7)
	now := int64(1000)
	br.Pick(now, "x", DstTLS443)
	lead := br.Leader()
	other := "a"
	if lead == "a" {
		other = "b"
	}
	for i := 0; i < 6; i++ {
		now += 2000
		r := bulk(lead, now, 100) // 10 MB/s
		r.AnswerMs = 900
		br.Observe(r)
		r = bulk(other, now, 64_000) // 16 KB/s
		r.AnswerMs = 60
		br.Observe(r)
		br.Pick(now, "x", DstTLS443)
	}
	if br.Leader() != lead || br.J.Count("lead_lag") != 0 {
		t.Fatalf("leader %q (lead_lag %d): the shaped %s took the lead from %s", br.Leader(), br.J.Count("lead_lag"), other, lead)
	}
}
