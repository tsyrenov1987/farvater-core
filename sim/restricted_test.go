package sim

import (
	"testing"

	"github.com/tsyrenov1987/farvater-core/brain"
)

// checkingPolicy drives the brain the way the switchboard does: when no path
// connects, it checks allow-listed sites directly at most once a minute (they
// answer unless the network itself is down) and, if they answer, moves the
// brain to the network's restricted variant.
type checkingPolicy struct {
	BrainPolicy
	net      Network
	probed   bool
	probedAt int64
	checks   int
}

func (p *checkingPolicy) Observe(r brain.Receipt) {
	p.B.Observe(r)
	if !p.B.NetDown(r.AtMs) || p.probed && r.AtMs-p.probedAt < 60_000 {
		return
	}
	p.probed, p.probedAt = true, r.AtMs
	p.checks++
	if !p.net.IsDown(r.AtMs) {
		p.B.EnterRestricted(r.AtMs)
	}
}

func runChecking(sc Scenario, cfg brain.Config, white map[string]bool, mem *brain.Memory) (Result, *brain.Brain, *checkingPolicy) {
	in := infos(sc)
	for i := range in {
		in[i].White = white[in[i].ID]
	}
	b := brain.New(cfg, "cell", in, sc.Seed)
	b.UseMemory(mem, nil, 0)
	p := &checkingPolicy{BrainPolicy: BrainPolicy{B: b}, net: sc.Net}
	return Run(sc, p, b.Gov), b, p
}

// A mobile network that lets only allow-listed addresses through: seven paths
// never connect, one (w, last in the catalogue) does.
func scWhitelist(seed uint64) Scenario {
	var paths []PathModel
	for i := 0; i < 7; i++ {
		paths = append(paths, PathModel{ID: "n" + itoa(i), SNI: "n" + itoa(i) + ".ex", IP: "10.4.0." + itoa(i+1), Rail: "reality", RTTMs: int64(30 + 5*i), GoodputBps: 3_000_000, WireFailProb: 1})
	}
	paths = append(paths, PathModel{ID: "w", SNI: "w.ex", IP: "10.4.9.1", Rail: "reality", RTTMs: 80, GoodputBps: 2_000_000})
	return Scenario{Name: "whitelist", Seed: seed, Paths: paths, Work: Workload{N: 600, DurationMs: 10 * minute}}
}

// direct is the share of live flows started in [from, to) that were served on
// their first path, with no wait for a connect-stage retry.
func direct(res Result, from, to int64) float64 {
	n, ok := 0, 0
	for _, f := range res.Records {
		if f.Dead || f.StartMs < from || f.StartMs >= to {
			continue
		}
		n++
		if f.Success && !f.Retried {
			ok++
		}
	}
	if n == 0 {
		return 0
	}
	return float64(ok) / float64(n)
}

// The restricted network, met for the first time and met again, over twenty
// workloads. The first time, the allow-listed check lets the brain count the
// silent paths' failures (the network is up), so it finds the path that gets
// through sooner than before; met again, memory serves it at once. Per
// workload it is never worse, and no path leaves the fan.
func TestRestrictedNetworkRemembered(t *testing.T) {
	end := 10 * minute
	var before, first, again float64
	const n = 20
	for seed := uint64(31); seed < 31+n; seed++ {
		plain, _ := runOurs(scWhitelist(seed))
		chk, b1, _ := runChecking(scWhitelist(seed), brain.DefaultConfig(), nil, brain.NewMemory())
		met, b2, _ := runChecking(scWhitelist(seed+100), brain.DefaultConfig(), nil, b1.Remember(end))
		plainMet, _ := runOurs(scWhitelist(seed + 100))
		p, c, m, pm := direct(plain, 0, minute), direct(chk, 0, minute), direct(met, 0, minute), direct(plainMet, 0, minute)
		before, first, again = before+p, first+c, again+m
		if c < p-0.02 || m < pm-0.02 || chk.SuccessRate(0, end) < plain.SuccessRate(0, end)-0.01 || met.SuccessRate(0, end) < plainMet.SuccessRate(0, end)-0.01 {
			t.Errorf("workload %d: worse than before: first minute %.3f vs %.3f, met again %.3f vs %.3f", seed, c, p, m, pm)
		}
		if b2.Leader() != "w" {
			t.Errorf("workload %d: met again, leader %q, want w", seed, b2.Leader())
		}
		floor := brain.DefaultConfig().FloorMs
		for _, path := range scWhitelist(seed).Paths {
			if g := met.MaxGapMs(path.ID, end); g > floor+2*minute {
				t.Fatalf("%s left the fan: %.1f min without a flow", path.ID, float64(g)/float64(minute))
			}
		}
	}
	labelled, _, _ := runChecking(scWhitelist(31), brain.DefaultConfig(), map[string]bool{"w": true}, brain.NewMemory())
	t.Logf("served on the first path in the first minute, mean of %d workloads: before %.3f, first time %.3f, met again %.3f; first time with the catalogue's allow-list label (one workload) %.3f",
		n, before/n, first/n, again/n, direct(labelled, 0, minute))
	if first/n < before/n+0.2 || again/n < 0.9 {
		t.Fatalf("restricted networks must be served sooner: before %.3f, first time %.3f, met again %.3f", before/n, first/n, again/n)
	}
}

// The whole fleet shut out for three minutes while the network is up: the
// brain takes it for a restricted network, and returns to the plain one once
// the paths connect again, serving as well as without the check.
func TestRestrictedEndsWhenThePathsReturn(t *testing.T) {
	sc := Scenario{Seed: 59, Work: Workload{N: 1600, DurationMs: 10 * minute}, Paths: carriers(4, false)}
	for i := range sc.Paths {
		sc.Paths[i].WireDeadFrom, sc.Paths[i].WireDeadTo = onset, onset+3*minute
	}
	plain, _ := runOurs(sc)
	chk, b, p := runChecking(sc, brain.DefaultConfig(), nil, nil)
	after := onset + 3*minute + 30_000
	t.Logf("served after the paths return: plain %.3f (first path %.3f), with the check %.3f (%.3f); checks %d, restricted_on %d, restricted_off %d, ctx %s",
		plain.SuccessRate(after, 1<<62), direct(plain, after, 1<<62), chk.SuccessRate(after, 1<<62), direct(chk, after, 1<<62), p.checks, b.J.Count("restricted_on"), b.J.Count("restricted_off"), b.Ctx())
	if b.J.Count("restricted_on") != 1 || b.J.Count("restricted_off") != 1 || b.Ctx() != "cell" {
		t.Fatalf("restricted_on %d, restricted_off %d, ctx %s: want one of each and back on cell", b.J.Count("restricted_on"), b.J.Count("restricted_off"), b.Ctx())
	}
	if chk.SuccessRate(after, 1<<62) < plain.SuccessRate(after, 1<<62)-0.01 || direct(chk, after, 1<<62) < direct(plain, after, 1<<62)-0.02 {
		t.Fatal("after the restriction the check must serve as well as without it")
	}
}

// Every scenario of the suite, driven with the restricted-network check on:
// where the check moves the brain, service must not get worse.
func TestRestrictedCheckNoRegression(t *testing.T) {
	healthyLead := func(seed uint64, lead PathModel) Scenario {
		return Scenario{Seed: seed, Work: Workload{N: 1600, DurationMs: 10 * minute}, Paths: append([]PathModel{lead}, healthyAlts()...)}
	}
	scs := map[string]Scenario{
		"fast-cut":     scFastCut(1, 30, 600),
		"all-healthy":  {Seed: 2, Paths: carriers(3, false), Work: Workload{N: 600, DurationMs: 30 * minute}},
		"dead-dst":     {Seed: 4, Paths: carriers(3, false), Work: Workload{N: 600, DurationMs: 30 * minute, DeadDstProb: 0.1}},
		"outage":       {Seed: 5, Paths: carriers(3, false), Net: Network{Down: [][2]int64{{10 * minute, 12 * minute}}}, Work: Workload{N: 600, DurationMs: 30 * minute}},
		"freeze":       {Seed: 6, Paths: carriers(5, true), Net: Network{FreezeRule: true}, Work: Workload{N: 600, DurationMs: 30 * minute, BurstProb: 0.3, BurstSize: 6}},
		"no-starve":    scFastCut(7, 60, 1200),
		"reset-storm":  healthyLead(7, PathModel{ID: "lead", SNI: "L.ex", IP: "10.2.9.9", Rail: "reality", RTTMs: 20, GoodputBps: 3_000_000, ResetAtBytes: 8 * 1024, ResetOnsetMs: onset}),
		"blackhole":    healthyLead(11, PathModel{ID: "lead", SNI: "L.ex", IP: "10.2.9.9", Rail: "reality", RTTMs: 20, GoodputBps: 3_000_000, BlackholeFrom: onset}),
		"wire-storm":   {Seed: 41, Work: Workload{N: 1600, DurationMs: 10 * minute}, Paths: append(carriers(3, false), PathModel{ID: "flaky", SNI: "f.ex", IP: "10.5.0.1", Rail: "ws", RTTMs: 50, GoodputBps: 2_000_000, WireFailProb: 0.5})},
		"late-onset":   {Seed: 3, Work: Workload{N: 600, DurationMs: 30 * minute}, Paths: []PathModel{{ID: "carrier-then-cut", SNI: "a.example", IP: "10.0.0.1", RTTMs: 40, CutAtBytes: 20 * 1024, OnsetMs: 10 * minute, GoodputBps: 2_000_000}, {ID: "slow-carrier", SNI: "b.example", IP: "10.0.0.2", RTTMs: 150, GoodputBps: 1_500_000}, {ID: "mid-cut", SNI: "c.example", IP: "10.0.0.3", RTTMs: 60, CutAtBytes: 20 * 1024, GoodputBps: 3_000_000}}},
		"coord-storm":  {Seed: 23, Work: Workload{N: 1800, DurationMs: 10 * minute}, Paths: []PathModel{{ID: "d1", SNI: "d1.ex", IP: "10.3.0.1", Rail: "reality", RTTMs: 25, GoodputBps: 3_000_000, BlackholeFrom: onset}, {ID: "d2", SNI: "d2.ex", IP: "10.3.0.2", Rail: "reality", RTTMs: 30, GoodputBps: 3_000_000, ResetAtBytes: 8 * 1024, ResetOnsetMs: onset}, {ID: "d3", SNI: "d3.ex", IP: "10.3.0.3", Rail: "xhttp", RTTMs: 35, GoodputBps: 2_500_000, BlackholeFrom: onset}, {ID: "d4", SNI: "d4.ex", IP: "10.3.0.4", Rail: "ws", RTTMs: 40, GoodputBps: 2_500_000, BlackholeFrom: onset}, {ID: "surv1", SNI: "s1.ex", IP: "10.3.9.1", Rail: "hy2", RTTMs: 70, GoodputBps: 2_000_000, WireFailProb: 0.02}, {ID: "surv2", SNI: "s2.ex", IP: "10.3.9.2", Rail: "xhttp", RTTMs: 90, GoodputBps: 2_000_000, WireFailProb: 0.02}}},
		"block-event":  {Seed: 47, Work: Workload{N: 1600, DurationMs: 10 * minute}, Paths: []PathModel{{ID: "b1", SNI: "b1.ex", IP: "10.7.0.1", Rail: "reality", RTTMs: 20, GoodputBps: 3_000_000, WireDeadFrom: onset}, {ID: "b2", SNI: "b2.ex", IP: "10.7.0.2", Rail: "reality", RTTMs: 25, GoodputBps: 3_000_000, WireDeadFrom: onset}, {ID: "b3", SNI: "b3.ex", IP: "10.7.0.3", Rail: "xhttp", RTTMs: 30, GoodputBps: 3_000_000, WireDeadFrom: onset}, {ID: "b4", SNI: "b4.ex", IP: "10.7.0.4", Rail: "ws", RTTMs: 35, GoodputBps: 3_000_000, WireDeadFrom: onset}, {ID: "s1", SNI: "s1.ex", IP: "10.7.9.1", Rail: "hy2", RTTMs: 70, GoodputBps: 2_000_000}, {ID: "s2", SNI: "s2.ex", IP: "10.7.9.2", Rail: "xhttp", RTTMs: 90, GoodputBps: 2_000_000}}},
		"block-most":   {Seed: 53, Work: Workload{N: 1600, DurationMs: 10 * minute}, Paths: []PathModel{{ID: "m1", SNI: "m1.ex", IP: "10.8.0.1", Rail: "reality", RTTMs: 20, GoodputBps: 3_000_000, WireDeadFrom: onset}, {ID: "m2", SNI: "m2.ex", IP: "10.8.0.2", Rail: "reality", RTTMs: 25, GoodputBps: 3_000_000, WireDeadFrom: onset}, {ID: "m3", SNI: "m3.ex", IP: "10.8.0.3", Rail: "xhttp", RTTMs: 30, GoodputBps: 3_000_000, WireDeadFrom: onset}, {ID: "m4", SNI: "m4.ex", IP: "10.8.0.4", Rail: "ws", RTTMs: 35, GoodputBps: 3_000_000, WireDeadFrom: onset}, {ID: "m5", SNI: "m5.ex", IP: "10.8.0.5", Rail: "hy2", RTTMs: 40, GoodputBps: 3_000_000, WireDeadFrom: onset}, {ID: "s1", SNI: "s1.ex", IP: "10.8.9.1", Rail: "reality", RTTMs: 90, GoodputBps: 2_000_000}}},
		"handshake-dp": {Seed: 43, Work: Workload{N: 1600, DurationMs: 10 * minute}, Paths: []PathModel{{ID: "h1", SNI: "h1.ex", IP: "10.6.0.1", Rail: "reality", RTTMs: 30, GoodputBps: 3_000_000, WireFailProb: 0.9}, {ID: "h2", SNI: "h2.ex", IP: "10.6.0.2", Rail: "reality", RTTMs: 35, GoodputBps: 3_000_000, WireFailProb: 0.9}, {ID: "ok", SNI: "ok.ex", IP: "10.6.9.1", Rail: "xhttp", RTTMs: 90, GoodputBps: 2_000_000, WireFailProb: 0.05}}},
	}
	for name, sc := range scs {
		plain, _ := runOurs(sc)
		chk, b, p := runChecking(sc, brain.DefaultConfig(), nil, nil)
		o, c := plain.SuccessRate(0, 1<<62), chk.SuccessRate(0, 1<<62)
		od, cd := direct(plain, 0, 1<<62), direct(chk, 0, 1<<62)
		t.Logf("%-12s served plain %.3f (first path %.3f), with the check %.3f (%.3f); checks %d, restricted_on %d, restricted_off %d", name, o, od, c, cd, p.checks, b.J.Count("restricted_on"), b.J.Count("restricted_off"))
		if c < o-0.01 || cd < od-0.02 {
			t.Errorf("%s: the restricted-network check made service worse: %.3f vs %.3f, first path %.3f vs %.3f", name, c, o, cd, od)
		}
	}
}
