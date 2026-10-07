package sim

import (
	"testing"

	"github.com/tsyrenov1987/farvater-core/brain"
)

// kilvaterFleet is four servers reached by the private HTTPS transport, which
// carries many streams over one connection.
func kilvaterFleet() []PathModel {
	var out []PathModel
	for i, rtt := range []int64{40, 55, 70, 90} {
		ip, sni, n := "10.9.0."+itoa(i+1), "s"+itoa(i)+".example", itoa(i)
		out = append(out, PathModel{ID: "k" + n, SNI: sni, IP: ip, Rail: "kilvater", Reuses: true, RTTMs: rtt, GoodputBps: 3_000_000, WireFailProb: 0.01})
	}
	return out
}

// xhttpFleet is the same four servers reached by XHTTP, which handshakes per flow.
func xhttpFleet() []PathModel {
	var out []PathModel
	for i, rtt := range []int64{40, 55, 70, 90} {
		ip, sni, n := "10.9.0."+itoa(i+1), "s"+itoa(i)+".example", itoa(i)
		out = append(out, PathModel{ID: "x" + n, SNI: sni, IP: ip, Rail: "xhttp", RTTMs: rtt, GoodputBps: 3_000_000, WireFailProb: 0.01})
	}
	return out
}

// TestStealthKilvater measures the private HTTPS transport against the same
// fleet reached by XHTTP, under the behavioural-freeze rule and a bursty
// workload, with no handshake governor so the comparison is of the transports
// alone. Because Kilvater carries many streams over one handshake, it trips the
// ">3 handshakes to one SNI in 350 ms" rule far less, so it freezes less and
// delivers more. On the wire it stays HTTP-like, so it holds no reveals edge
// over XHTTP. Read it with -v.
func TestStealthKilvater(t *testing.T) {
	const end, seeds = 30 * minute, uint64(5)
	run := func(fleet func() []PathModel) (served float64, freezes int, reveals, servers float64) {
		for seed := uint64(71); seed < 71+seeds; seed++ {
			paths := fleet()
			sc := Scenario{Name: "freeze", Seed: seed, Paths: paths, Net: Network{FreezeRule: true},
				Work: Workload{N: 6000, DurationMs: end, BurstProb: 0.5, BurstSize: 8}}
			b := brain.New(brain.DefaultConfig(), "sim", infos(sc), sc.Seed)
			res := Run(sc, &BrainPolicy{B: b}, nil) // nil governor: isolate the transport
			served += res.SuccessRate(0, end) / float64(seeds)
			freezes += res.Net.Freezes
			e := Measure(res, paths, end)
			reveals += e.RevealsPerHour / float64(seeds)
			servers += e.ServersPerHour / float64(seeds)
		}
		return
	}
	ks, kf, kr, ksv := run(kilvaterFleet)
	xs, xf, xr, xsv := run(xhttpFleet)
	t.Logf("kilvater: served %.3f freezes %d reveals/h %.1f servers/h %.1f", ks, kf, kr, ksv)
	t.Logf("xhttp:    served %.3f freezes %d reveals/h %.1f servers/h %.1f", xs, xf, xr, xsv)

	if xf == 0 {
		t.Fatalf("the workload did not stress the freeze rule (xhttp froze %d times)", xf)
	}
	if kf >= xf {
		t.Fatalf("kilvater should freeze less than xhttp: kilvater %d, xhttp %d", kf, xf)
	}
	if ks < xs {
		t.Fatalf("kilvater should deliver at least as well as xhttp: kilvater %.3f, xhttp %.3f", ks, xs)
	}
}
