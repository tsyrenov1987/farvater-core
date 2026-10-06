package sim

import (
	"testing"

	"github.com/tsyrenov1987/farvater-core/brain"
)

// An observer learns from a failure that lights up, within a second, a server
// it had not seen for ten minutes; a server seen lately, or a dial a second and
// a half later, tells it nothing new.
func TestMeasureCountsReveals(t *testing.T) {
	paths := []PathModel{{ID: "a", IP: "A"}, {ID: "a2", IP: "A"}, {ID: "b", IP: "B"}, {ID: "c", IP: "C", NotHTTP: true}}
	res := Result{Dials: []Dial{
		{At: 0, EndAt: 100, Path: "a", OK: true},
		{At: 500, EndAt: 600, Path: "a2", OK: true},  // a second tunnel to A
		{At: 1000, EndAt: 3000, Path: "a"},           // fails...
		{At: 3500, EndAt: 3600, Path: "b", OK: true}, // ...and B lights up within a second
		{At: 9000, EndAt: 10_000, Path: "a"},         // fails, but B was seen 6.5 s before
		{At: 10_500, EndAt: 10_600, Path: "b", OK: true},
		{At: 19_000, EndAt: 20_000, Path: "a", Explore: true}, // fails; C comes 1.5 s later
		{At: 21_500, EndAt: 21_600, Path: "c", OK: true},
	}}
	want := Exposure{ServersPerHour: 3, TunnelsPer10Min: 4, ExplorePerHour: 1, FailedPerHour: 3, RevealsPerHour: 1}
	if e := Measure(res, paths, hourMs); e != want {
		t.Fatalf("exposure %+v, want %+v", e, want)
	}
	res.Dials[7].At = 20_900 // C, which looks like no HTTP, now lights up within the second
	want.RevealsPerHour, want.NotHTTPAfterFail = 2, 1
	if e := Measure(res, paths, hourMs); e != want {
		t.Fatalf("exposure %+v, want %+v", e, want)
	}
}

// A run logs every dial an observer sees: each flow's first, and the
// connect-stage retry of a flow that got no answer.
func TestDialsLogRetries(t *testing.T) {
	sc := Scenario{Name: "one dead", Seed: 5, Work: Workload{N: 600, DurationMs: 10 * minute}, Paths: []PathModel{
		{ID: "dead", SNI: "d.ex", IP: "10.1.0.1", Rail: "reality", RTTMs: 20, WireDeadFrom: 1},
		{ID: "live", SNI: "l.ex", IP: "10.1.0.2", Rail: "xhttp", RTTMs: 40, GoodputBps: 2_000_000},
	}}
	res, _ := runOurs(sc)
	retried := 0
	for _, r := range res.Records {
		if r.Retried {
			retried++
		}
	}
	if retried == 0 || len(res.Dials) != len(res.Records)+retried {
		t.Fatalf("%d dials for %d flows, %d of them retried", len(res.Dials), len(res.Records), retried)
	}
}

func delivery(path string, at int64) brain.Receipt {
	return brain.Receipt{Path: path, Ctx: "sim", AtMs: at, WireReadyMs: 20, FirstByteMs: 30, Down: 64 * brain.KB, DownAtFail: -1, End: brain.EndRemoteFin}
}

// The prototype retries a flow on its own server alone, and uses QUIC on a
// server only once TCP there has delivered, and not for five minutes after
// QUIC there failed.
func TestChromeStaysOnTheServer(t *testing.T) {
	paths := []PathModel{
		{ID: "r0", SNI: "s0", IP: "A", Rail: "reality"}, {ID: "h0", SNI: "s0", IP: "A", Rail: "hy2", NotHTTP: true},
		{ID: "r1", SNI: "s1", IP: "B", Rail: "reality"}, {ID: "x1", SNI: "s1", IP: "B", Rail: "xhttp"},
	}
	b := brain.New(ChromeConfig(), "sim", infos(Scenario{Paths: paths}), 1)
	p := NewChromePolicy(b, paths)
	server := map[string]string{}
	for _, m := range paths {
		server[m.ID] = m.IP
	}
	now := int64(1000)
	pick := func() brain.Decision {
		now += 100
		d := p.Pick(now, "h", brain.DstTLS443)
		if d.Secondary != "" && server[d.Secondary] != server[d.Primary] {
			t.Fatalf("a stand-in off the primary's server: %+v", d)
		}
		return d
	}
	pick()
	for range 8 { // QUIC on A delivers best: the brain leads with it
		now += 100
		p.Observe(delivery("h0", now))
	}
	if d := pick(); b.Leader() != "h0" || d.Primary != "r0" || d.Secondary != "" {
		t.Fatalf("leader %s, %+v: before TCP delivered on A the flow goes over A's TCP, with no stand-in", b.Leader(), d)
	}
	p.Observe(delivery("r0", now))
	if d := pick(); d.Primary != "h0" || d.Secondary != "r0" {
		t.Fatalf("%+v: once TCP delivered on A, QUIC there, TCP there as the stand-in", d)
	}
	p.Observe(brain.Receipt{Path: "h0", Ctx: "sim", AtMs: now, WireReadyMs: 20, FirstByteMs: -1, DownAtFail: -1, End: brain.EndTimeout})
	for end := now + quicBrokenMs - 1000; now < end; {
		if d := pick(); d.Primary == "h0" || d.Secondary == "h0" {
			t.Fatalf("%+v: QUIC on A within five minutes of failing there", d)
		}
	}
}

// fieldFleet is a fleet shaped like a real one: four servers, each with REALITY
// and XHTTP over TCP and Hysteria 2 under Salamander on one address and name.
func fieldFleet() []PathModel {
	var out []PathModel
	for i, rtt := range []int64{40, 55, 70, 90} {
		ip, sni, n := "10.9.0."+itoa(i+1), "s"+itoa(i)+".example", itoa(i)
		out = append(out,
			PathModel{ID: "r" + n, SNI: sni, IP: ip, Rail: "reality", RTTMs: rtt, GoodputBps: 3_000_000, WireFailProb: 0.01},
			PathModel{ID: "x" + n, SNI: sni, IP: ip, Rail: "xhttp", RTTMs: rtt + 20, GoodputBps: 2_500_000, WireFailProb: 0.01},
			PathModel{ID: "h" + n, SNI: sni, IP: ip, Rail: "hy2", NotHTTP: true, RTTMs: rtt, GoodputBps: 3_500_000, WireFailProb: 0.02})
	}
	return out
}

// TestStealthReport runs over an hour of a realistic fleet, under the blocks seen
// in the field: the current core, the core with half its exploration share, the
// core with the prototype's rarer exploration alone, and the whole browser-like
// prototype. It reports delivery against what an observer can count. Read it with
// -v; the decision on the prototype is taken on these numbers. (A floor of 30
// minutes or a share of 0.05 as the default breaks invariants checked elsewhere:
// every path in the fan of a restricted network, the cut16 signature, a dead
// destination never moving the leader. Half the share breaks none.)
func TestStealthReport(t *testing.T) {
	const at = 20 * minute // the block starts here
	cases := []struct {
		name  string
		block func(p *PathModel)
	}{
		{"calm", func(*PathModel) {}},
		{"2 of 4 servers blocked", func(p *PathModel) {
			if p.IP == "10.9.0.1" || p.IP == "10.9.0.2" {
				p.WireDeadFrom = at
			}
		}},
		{"REALITY reset", func(p *PathModel) {
			if p.Rail == "reality" {
				p.ResetAtBytes, p.ResetOnsetMs = 8*1024, at
			}
		}},
		{"foreign UDP cut", func(p *PathModel) {
			if p.Rail == "hy2" {
				p.WireDeadFrom = 1
			}
		}},
		{"16 KB throttle on 2", func(p *PathModel) {
			if p.Rail != "hy2" && (p.IP == "10.9.0.1" || p.IP == "10.9.0.2") {
				p.CutAtBytes, p.OnsetMs = 16*1024, at
			}
		}},
	}
	const end, seeds = 60 * minute, 5
	for _, c := range cases {
		half := brain.DefaultConfig()
		half.ExploreShare = 0.1
		for _, mode := range []struct {
			name   string
			cfg    brain.Config
			chrome bool
		}{{"farvater", brain.DefaultConfig(), false}, {"share .1", half, false}, {"rarer", ChromeConfig(), false}, {"chrome", ChromeConfig(), true}} {
			var all, after, first float64
			var e Exposure
			for seed := uint64(31); seed < 31+seeds; seed++ {
				paths := fieldFleet()
				for i := range paths {
					c.block(&paths[i])
				}
				sc := Scenario{Name: c.name, Seed: seed, Paths: paths, Work: Workload{N: 7200, DurationMs: end}}
				var res Result
				if mode.chrome {
					b := brain.New(mode.cfg, "sim", infos(sc), sc.Seed)
					res = Run(sc, NewChromePolicy(b, paths), b.Gov)
				} else {
					res, _ = runOursCfg(sc, mode.cfg)
				}
				m := Measure(res, paths, end)
				if s := res.SuccessRate(0, end); s <= 0 || s > 1 || m.ServersPerHour > 4 || m.TunnelsPer10Min > 12 {
					t.Fatalf("%s/%s: served %.3f, %+v", c.name, mode.name, s, m)
				}
				all += res.SuccessRate(0, end) / seeds
				after += res.SuccessRate(at, end) / seeds
				first += res.SuccessRate(at, at+2*minute) / seeds
				e.ServersPerHour += m.ServersPerHour / seeds
				e.TunnelsPer10Min += m.TunnelsPer10Min / seeds
				e.ExplorePerHour += m.ExplorePerHour / seeds
				e.FailedPerHour += m.FailedPerHour / seeds
				e.RevealsPerHour += m.RevealsPerHour / seeds
				e.NotHTTPAfterFail += m.NotHTTPAfterFail / seeds
			}
			t.Logf("%-22s %-8s served %.3f (after the block %.3f, its first 2 min %.3f) | servers/h %.1f tunnels/10min %.1f explore/h %.0f failed/h %.0f reveals/h %.1f not-HTTP-after-fail/h %.0f",
				c.name, mode.name, all, after, first, e.ServersPerHour, e.TunnelsPer10Min, e.ExplorePerHour, e.FailedPerHour, e.RevealsPerHour, e.NotHTTPAfterFail)
		}
	}
}
