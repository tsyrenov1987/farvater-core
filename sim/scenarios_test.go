package sim

import (
	"testing"

	"github.com/tsyrenov1987/farvater-core/brain"
)

const minute = int64(60_000)

func infos(sc Scenario) []brain.PathInfo {
	out := make([]brain.PathInfo, 0, len(sc.Paths))
	for _, p := range sc.Paths {
		out = append(out, brain.PathInfo{ID: p.ID, SNI: p.SNI, IP: p.IP, Rail: p.Rail, NotHTTP: p.NotHTTP})
	}
	return out
}

func runOurs(sc Scenario) (Result, *brain.Brain) {
	return runOursCfg(sc, brain.DefaultConfig())
}

func runOursCfg(sc Scenario, cfg brain.Config) (Result, *brain.Brain) {
	b := brain.New(cfg, "sim", infos(sc), sc.Seed)
	return Run(sc, &BrainPolicy{B: b}, b.Gov), b
}

// noBreaker is DefaultConfig with the circuit breaker switched off: the pure
// slow learner. TSPU scenarios must show the breaker beating it.
func noBreaker() brain.Config {
	cfg := brain.DefaultConfig()
	cfg.Breaker.Enabled = false
	return cfg
}

func scFastCut(seed uint64, durMin int64, n int) Scenario {
	return Scenario{Name: "fast-ping-cut vs slow-carrier", Seed: seed,
		Paths: []PathModel{
			{ID: "fast-cut", SNI: "a.example", IP: "10.0.0.1", RTTMs: 15, CutAtBytes: 18 * 1024, GoodputBps: 3_000_000},
			{ID: "carrier", SNI: "b.example", IP: "10.0.0.2", RTTMs: 90, GoodputBps: 2_000_000},
			{ID: "mid-cut", SNI: "c.example", IP: "10.0.0.3", RTTMs: 60, CutAtBytes: 20 * 1024, GoodputBps: 3_000_000},
		},
		Work: Workload{N: n, DurationMs: durMin * minute}}
}

func carriers(n int, sameSNI bool) []PathModel {
	var out []PathModel
	for i := 0; i < n; i++ {
		sni := "p" + itoa(i) + ".example"
		if sameSNI {
			sni = "cdn.example"
		}
		out = append(out, PathModel{ID: "c" + itoa(i), SNI: sni, IP: "10.0.1." + itoa(i+1), RTTMs: int64(30 + 20*i), GoodputBps: 2_000_000})
	}
	return out
}

// The core claim: a latency selector picks the fastest-answering path that does
// not carry; farvater-core finds the one that does. The baseline MUST fail here,
// otherwise the scenario no longer discriminates.
func TestFastPingCutVsSlowCarrier(t *testing.T) {
	sc := scFastCut(1, 30, 600)
	ours, b := runOurs(sc)
	base, u := RunURLTest(sc)
	o, bs := ours.SuccessRate(0, 1<<62), base.SuccessRate(0, 1<<62)
	t.Logf("success: farvater %.3f, urltest %.3f (checks %d, changes %d); leader=%s; shares=%v", o, bs, u.Checks, u.Changes, b.Leader(), ours.ShareByPath())
	if bs >= 0.6 {
		t.Fatalf("baseline must fail on this scenario, got %.2f", bs)
	}
	if o < 0.88 {
		t.Fatalf("farvater success %.2f < 0.88", o)
	}
	if o-bs < 0.3 {
		t.Fatalf("gap %.2f < 0.3", o-bs)
	}
	if b.Leader() != "carrier" {
		t.Fatalf("leader %q, want carrier", b.Leader())
	}
	// cut16 is the SLOW learner's persistent fingerprint. With the breaker on,
	// the bad rail is starved of flows too fast for the fingerprint to form,
	// which is the point. Isolate the fingerprint logic with the breaker off.
	_, bOff := runOursCfg(sc, noBreaker())
	if !bOff.State("fast-cut").Cut16 {
		t.Errorf("cut16 signature not detected on fast-cut (breaker off)")
	}
}

func TestAllHealthyNoRegression(t *testing.T) {
	sc := Scenario{Name: "all healthy", Seed: 2, Paths: carriers(3, false), Work: Workload{N: 600, DurationMs: 30 * minute}}
	ours, b := runOurs(sc)
	base, _ := RunURLTest(sc)
	o, bs := ours.SuccessRate(0, 1<<62), base.SuccessRate(0, 1<<62)
	t.Logf("success: farvater %.3f, urltest %.3f; shares=%v leader=%s", o, bs, ours.ShareByPath(), b.Leader())
	if o < bs-0.03 {
		t.Fatalf("farvater %.3f worse than baseline %.3f", o, bs)
	}
	if sh := ours.ShareByPath()[b.Leader()]; sh < 0.7 {
		t.Fatalf("leader share %.2f < 0.7: selection flaps", sh)
	}
}

func TestLateOnsetThrottle(t *testing.T) {
	sc := Scenario{Name: "late onset", Seed: 3,
		Paths: []PathModel{
			{ID: "carrier-then-cut", SNI: "a.example", IP: "10.0.0.1", RTTMs: 40, CutAtBytes: 20 * 1024, OnsetMs: 10 * minute, GoodputBps: 2_000_000},
			{ID: "slow-carrier", SNI: "b.example", IP: "10.0.0.2", RTTMs: 150, GoodputBps: 1_500_000},
			{ID: "mid-cut", SNI: "c.example", IP: "10.0.0.3", RTTMs: 60, CutAtBytes: 20 * 1024, GoodputBps: 3_000_000},
		},
		Work: Workload{N: 600, DurationMs: 30 * minute}}
	ours, b := runOurs(sc)
	base, _ := RunURLTest(sc)
	o, bs := ours.SuccessRate(13*minute, 30*minute), base.SuccessRate(13*minute, 30*minute)
	t.Logf("after onset (13–30 min): farvater %.3f, urltest %.3f; leader=%s; journal=%d", o, bs, b.Leader(), len(b.J.Entries()))
	if bs >= 0.6 {
		t.Fatalf("baseline must fail after onset, got %.2f", bs)
	}
	if o < 0.85 {
		t.Fatalf("farvater after onset %.2f < 0.85", o)
	}
	if b.Leader() != "slow-carrier" {
		t.Fatalf("leader %q, want slow-carrier", b.Leader())
	}
}

func TestDeadDestinationDoesNotPunishPath(t *testing.T) {
	sc := Scenario{Name: "dead destination", Seed: 4, Paths: carriers(3, false), Work: Workload{N: 600, DurationMs: 30 * minute, DeadDstProb: 0.1}}
	ours, b := runOurs(sc)
	st := b.State(b.Leader())
	t.Logf("leader=%s deliv=%.3f fb=%.3f dropped=%d switches=%d live-success=%.3f", b.Leader(), st.DelivMean(), st.FbMean(), b.Dropped, b.J.Count("lead_switch")+b.J.Count("lead_stall"), ours.SuccessRate(0, 1<<62))
	if n := b.J.Count("lead_switch") + b.J.Count("lead_stall"); n != 0 {
		t.Fatalf("leader changed %d times because of a dead destination", n)
	}
	if st.DelivMean() < 0.85 {
		t.Fatalf("leader delivery posterior %.2f fell because of a dead destination", st.DelivMean())
	}
	if b.Dropped == 0 {
		t.Errorf("destination quarantine never engaged")
	}
	if o := ours.SuccessRate(0, 1<<62); o < 0.95 {
		t.Fatalf("live-destination success %.2f < 0.95", o)
	}
}

func TestNetworkOutageIsNotEvidence(t *testing.T) {
	sc := Scenario{Name: "outage", Seed: 5, Paths: carriers(3, false), Net: Network{Down: [][2]int64{{10 * minute, 12 * minute}}}, Work: Workload{N: 600, DurationMs: 30 * minute}}
	ours, b := runOurs(sc)
	t.Logf("dropped=%d leader=%s fb=%.3f after=%.3f", b.Dropped, b.Leader(), b.State(b.Leader()).FbMean(), ours.SuccessRate(13*minute, 30*minute))
	if b.Dropped == 0 {
		t.Fatalf("outage receipts were counted as evidence")
	}
	if n := b.J.Count("lead_switch") + b.J.Count("lead_stall"); n != 0 {
		t.Fatalf("leader changed %d times during an outage", n)
	}
	if o := ours.SuccessRate(13*minute, 30*minute); o < 0.95 {
		t.Fatalf("success after outage %.2f < 0.95", o)
	}
}

// Hypothesis H-freeze: >3 TLS handshakes to one SNI inside ~350 ms freeze the
// path set for ~120 s. A start-up race and page loads trigger it; the governor does not.
func TestHandshakeBurstFreezeHypothesis(t *testing.T) {
	sc := Scenario{Name: "freeze", Seed: 6, Paths: carriers(5, true), Net: Network{FreezeRule: true},
		Work: Workload{N: 600, DurationMs: 30 * minute, BurstProb: 0.3, BurstSize: 6}}
	ours, _ := runOurs(sc)
	base, _ := RunURLTest(sc)
	t.Logf("first 2 min: farvater %.3f, urltest %.3f; overall: %.3f vs %.3f; freezes: ours %d, base %d",
		ours.SuccessRate(0, 2*minute), base.SuccessRate(0, 2*minute), ours.SuccessRate(0, 1<<62), base.SuccessRate(0, 1<<62), ours.Net.Freezes, base.Net.Freezes)
	if bs := base.SuccessRate(0, 2*minute); bs >= 0.3 {
		t.Fatalf("baseline start-up race must freeze under H-freeze, got %.2f", bs)
	}
	if o := ours.SuccessRate(0, 1<<62); o < 0.9 {
		t.Fatalf("farvater overall %.2f < 0.9", o)
	}
	if ours.Net.Freezes != 0 {
		t.Fatalf("governor let %d freezes happen", ours.Net.Freezes)
	}
	for sni, ts := range ours.Net.Handshakes() {
		for i := range ts {
			n := 0
			for j := i; j < len(ts) && ts[j] < ts[i]+400; j++ {
				n++
			}
			if n > 2 {
				t.Fatalf("%s: %d handshakes inside 400 ms at t=%d", sni, n, ts[i])
			}
		}
	}
}

func TestNoPathStarved(t *testing.T) {
	sc := scFastCut(7, 60, 1200)
	ours, b := runOurs(sc)
	floor := brain.DefaultConfig().FloorMs
	for _, p := range sc.Paths {
		g := ours.MaxGapMs(p.ID, 60*minute)
		t.Logf("%s: max gap %.1f min, picks %d", p.ID, float64(g)/float64(minute), len(ours.Picks[p.ID]))
		if g > floor+2*minute {
			t.Fatalf("%s starved: %.1f min without a flow", p.ID, float64(g)/float64(minute))
		}
	}
	t.Logf("success %.3f leader=%s", ours.SuccessRate(0, 1<<62), b.Leader())
}
