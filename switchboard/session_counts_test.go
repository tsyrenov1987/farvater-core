package switchboard

import (
	"context"
	"testing"

	"github.com/tsyrenov1987/farvater-core/brain"
)

// The session's served and blocked counts go on across a network change,
// where a path's own counts are the new network's, and leave the
// switchboard's probes out: the journal's half-hour windows are their deltas.
func TestSessionCountsSpanNetworksAndLeaveProbesOut(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Ctx = "cell"
	cfg.ProbeURL = "https://speed.cloudflare.com/__down?bytes=262144"
	s, err := New(cfg, threeDead(t))
	if err != nil {
		t.Fatal(err)
	}
	s.probe = func(context.Context, []string) bool { return false }
	s.observe(delivered("a"))
	s.observe(delivered("a"))
	s.observe(wireFailed("b"))
	closedEarly := brain.Receipt{Path: "c", AtMs: nowMs(), WireReadyMs: 20, FirstByteMs: -1, DownAtFail: -1, End: brain.EndLocalClose, Dst: "h"}
	s.observe(closedEarly) // no answer and no block signature: neither
	probe := delivered("c")
	probe.Dst = "speed.cloudflare.com"
	s.observe(probe)
	failedProbe := wireFailed("c")
	failedProbe.Dst = "speed.cloudflare.com"
	s.observe(failedProbe)

	st := s.Status()
	if st.Served != 2 || st.Blocked != 1 {
		t.Fatalf("served %d blocked %d, want 2 and 1", st.Served, st.Blocked)
	}
	s.SetNetwork("wifi:0a1b2c3d")
	s.observe(wireFailed("a"))
	st = s.Status()
	for _, p := range st.Paths {
		if p.ID == "a" && (p.Served != 0 || p.Blocked != 1) {
			t.Fatalf("path a on the new network: served %d blocked %d, want 0 and 1", p.Served, p.Blocked)
		}
	}
	if st.Served != 2 || st.Blocked != 2 {
		t.Fatalf("after the network change: served %d blocked %d, want 2 and 2", st.Served, st.Blocked)
	}
}
