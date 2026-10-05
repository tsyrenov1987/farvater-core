package sim

import (
	"testing"

	"github.com/tsyrenov1987/farvater-core/brain"
)

// These scenarios model active TSPU interference that switches on mid-run and
// prove the circuit breaker reacts faster than the slow learner alone. Each
// scenario is run twice: with the breaker (DefaultConfig) and with it off
// (noBreaker). The breaker must win on the metric the impairment actually moves.

// onset is when the leader turns hostile; the doomed rail is the best one until
// then (the others carry a small wire-fail rate so the doomed rail leads).
const onset = int64(60_000)

func picksIn(res Result, rail string, from, to int64) int {
	n := 0
	for _, t := range res.Picks[rail] {
		if t >= from && t < to {
			n++
		}
	}
	return n
}

func healthyAlts() []PathModel {
	return []PathModel{
		{ID: "alt1", SNI: "a1.ex", IP: "10.2.0.1", Rail: "reality", RTTMs: 40, GoodputBps: 2_500_000, WireFailProb: 0.03},
		{ID: "alt2", SNI: "a2.ex", IP: "10.2.0.2", Rail: "xhttp", RTTMs: 60, GoodputBps: 2_000_000, WireFailProb: 0.03},
		{ID: "alt3", SNI: "a3.ex", IP: "10.2.0.3", Rail: "ws", RTTMs: 80, GoodputBps: 2_000_000, WireFailProb: 0.03},
	}
}

// TestResetStormFastDemote: the leader starts injecting RST on big flows at
// onset. A reset flow already got its first byte, so the connect-stage backup
// cannot rescue it — only a fast leader change helps. Success is the metric.
func TestResetStormFastDemote(t *testing.T) {
	mk := func() Scenario {
		return Scenario{Name: "reset-storm", Seed: 7, Work: Workload{N: 1600, DurationMs: 10 * minute},
			Paths: append([]PathModel{
				{ID: "lead", SNI: "L.ex", IP: "10.2.9.9", Rail: "reality", RTTMs: 20, GoodputBps: 3_000_000,
					ResetAtBytes: 8 * 1024, ResetOnsetMs: onset},
			}, healthyAlts()...)}
	}
	on, bOn := runOursCfg(mk(), brain.DefaultConfig())
	off, _ := runOursCfg(mk(), noBreaker())
	end := int64(10) * minute
	onPost := on.SuccessRate(onset, end)
	offPost := off.SuccessRate(onset, end)
	onMin := on.SuccessRate(onset, onset+minute)
	offMin := off.SuccessRate(onset, onset+minute)
	t.Logf("reset: post-onset success on=%.3f off=%.3f; first-min on=%.3f off=%.3f; trips=%d leader=%s",
		onPost, offPost, onMin, offMin, bOn.J.Count("lead_trip"), bOn.Leader())
	if bOn.J.Count("lead_trip") < 1 {
		t.Fatalf("breaker never tripped the leader")
	}
	if onPost < 0.85 {
		t.Fatalf("breaker post-onset success %.3f < 0.85", onPost)
	}
	if onMin < offMin+0.1 {
		t.Fatalf("breaker did not recover faster in the first minute: on=%.3f off=%.3f", onMin, offMin)
	}
}

// TestBlackholeFewerWastedAttempts: the leader connects but goes silent at
// onset. A flow with no first byte IS rescued by the connect-stage backup, so
// success stays high for both — the breaker's win is that far fewer flows even
// try the dead rail as primary (less wasted latency).
func TestBlackholeFewerWastedAttempts(t *testing.T) {
	mk := func() Scenario {
		return Scenario{Name: "blackhole", Seed: 11, Work: Workload{N: 1600, DurationMs: 10 * minute},
			Paths: append([]PathModel{
				{ID: "lead", SNI: "L.ex", IP: "10.2.9.9", Rail: "reality", RTTMs: 20, GoodputBps: 3_000_000,
					BlackholeFrom: onset},
			}, healthyAlts()...)}
	}
	on, bOn := runOursCfg(mk(), brain.DefaultConfig())
	off, _ := runOursCfg(mk(), noBreaker())
	end := int64(10) * minute
	onWaste := picksIn(on, "lead", onset, end)
	offWaste := picksIn(off, "lead", onset, end)
	t.Logf("blackhole: dead-rail primary picks post-onset on=%d off=%d; success on=%.3f off=%.3f; trips=%d",
		onWaste, offWaste, on.SuccessRate(onset, end), off.SuccessRate(onset, end), bOn.J.Count("lead_trip"))
	if bOn.J.Count("lead_trip") < 1 {
		t.Fatalf("breaker never tripped the silent leader")
	}
	if onWaste >= offWaste {
		t.Fatalf("breaker did not cut wasted attempts on the dead rail: on=%d off=%d", onWaste, offWaste)
	}
	if on.SuccessRate(onset, end) < 0.9 {
		t.Fatalf("backup should keep success high, got %.3f", on.SuccessRate(onset, end))
	}
}

// TestCoordinatedStormRecovers: four of six rails die at once, two survive. The
// breaker trips the dead rails so both primary and backup land on survivors;
// storm mode raises exploration to find them fast. The slow learner keeps
// dealing dead rails to both slots and fails more.
func TestCoordinatedStormRecovers(t *testing.T) {
	mk := func() Scenario {
		return Scenario{Name: "coordinated-storm", Seed: 23, Work: Workload{N: 1800, DurationMs: 10 * minute},
			Paths: []PathModel{
				{ID: "d1", SNI: "d1.ex", IP: "10.3.0.1", Rail: "reality", RTTMs: 25, GoodputBps: 3_000_000, BlackholeFrom: onset},
				{ID: "d2", SNI: "d2.ex", IP: "10.3.0.2", Rail: "reality", RTTMs: 30, GoodputBps: 3_000_000, ResetAtBytes: 8 * 1024, ResetOnsetMs: onset},
				{ID: "d3", SNI: "d3.ex", IP: "10.3.0.3", Rail: "xhttp", RTTMs: 35, GoodputBps: 2_500_000, BlackholeFrom: onset},
				{ID: "d4", SNI: "d4.ex", IP: "10.3.0.4", Rail: "ws", RTTMs: 40, GoodputBps: 2_500_000, BlackholeFrom: onset},
				{ID: "surv1", SNI: "s1.ex", IP: "10.3.9.1", Rail: "hy2", RTTMs: 70, GoodputBps: 2_000_000, WireFailProb: 0.02},
				{ID: "surv2", SNI: "s2.ex", IP: "10.3.9.2", Rail: "xhttp", RTTMs: 90, GoodputBps: 2_000_000, WireFailProb: 0.02},
			}}
	}
	on, bOn := runOursCfg(mk(), brain.DefaultConfig())
	off, _ := runOursCfg(mk(), noBreaker())
	end := int64(10) * minute
	deadWaste := func(res Result, from, to int64) int {
		n := 0
		for _, id := range []string{"d1", "d2", "d3", "d4"} {
			n += picksIn(res, id, from, to)
		}
		return n
	}
	onWaste := deadWaste(on, onset, onset+2*minute)
	offWaste := deadWaste(off, onset, onset+2*minute)
	onPost := on.SuccessRate(onset, end)
	trips := bOn.J.Count("lead_trip") + bOn.J.Count("trip")
	surv := bOn.Leader() == "surv1" || bOn.Leader() == "surv2"
	t.Logf("storm: dead-rail primary picks (first 2 min) on=%d off=%d; full-post success on=%.3f; trips=%d leader=%s(survivor=%v)",
		onWaste, offWaste, onPost, trips, bOn.Leader(), surv)
	if trips < 2 {
		t.Fatalf("storm should trip ≥2 rails, got %d", trips)
	}
	if !surv {
		t.Fatalf("breaker should settle on a survivor, leader=%s", bOn.Leader())
	}
	// The connect-stage diverse backup already rescues most flows (resilience by
	// design), so the breaker's win is sending far fewer flows into dead rails.
	if onWaste*2 > offWaste {
		t.Fatalf("breaker should roughly halve dead-rail attempts: on=%d off=%d", onWaste, offWaste)
	}
	if onPost < 0.95 {
		t.Fatalf("breaker post-onset success %.3f < 0.95", onPost)
	}
}
