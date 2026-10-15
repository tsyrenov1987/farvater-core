package sim

import (
	"testing"

	"github.com/tsyrenov1987/farvater-core/brain"
)

// Field case 15.10: on home Wi-Fi fifteen entries of the subscription let in
// only mobile networks and never connect; three paths carry. The catalogue
// marks those entries "cell".
func scWifiMobileOnly(seed uint64, labelled, onlyLabelledWork bool) Scenario {
	var paths []PathModel
	for i := 0; i < 15; i++ {
		p := PathModel{ID: "cdnv" + itoa(i), SNI: "x" + itoa(i) + ".ru", IP: "10.9.0.3", Rail: "xhttp", RTTMs: 35, GoodputBps: 2_000_000}
		if !onlyLabelledWork {
			p.WireDeadFrom = 1
		}
		if labelled {
			p.Net = "cell"
		}
		paths = append(paths, p)
	}
	for _, p := range []PathModel{
		{ID: "nl1", SNI: "eu11.example", IP: "10.9.1.1", Rail: "reality", RTTMs: 60, GoodputBps: 3_000_000},
		{ID: "rux21", SNI: "x9.ru", IP: "10.9.0.1", Rail: "xhttp", RTTMs: 45, GoodputBps: 2_000_000},
		{ID: "rux26", SNI: "x11.ru", IP: "10.9.0.1", Rail: "xhttp", RTTMs: 45, GoodputBps: 2_000_000},
	} {
		if onlyLabelledWork {
			p.WireDeadFrom = 1
		}
		paths = append(paths, p)
	}
	return Scenario{Name: "wifi, mobile-only entries", Seed: seed, Paths: paths,
		Work: Workload{N: 1800, DurationMs: 60 * minute, BurstProb: 0.3, BurstSize: 4}}
}

func runWifi(sc Scenario) (Result, *brain.Brain) {
	b := brain.New(brain.DefaultConfig(), "wifi:home", infos(sc), sc.Seed)
	b.UseMemory(nil, nil, 0)
	return Run(sc, &BrainPolicy{B: b}, b.Gov), b
}

func retriedShare(r Result) float64 {
	n := 0
	for _, f := range r.Records {
		if f.Retried {
			n++
		}
	}
	return float64(n) / float64(len(r.Records))
}

// The hint must cut the flows that wait on a dead mobile-only entry, and must
// not cost the case where those entries are the ones that work.
func TestMobileOnlyHintOnWifi(t *testing.T) {
	var plainR, hintR, plainOK, hintOK, revOK, revPlainOK float64
	const seeds = 8
	for seed := uint64(1); seed <= seeds; seed++ {
		plain, _ := runWifi(scWifiMobileOnly(seed, false, false))
		hint, _ := runWifi(scWifiMobileOnly(seed, true, false))
		rev, _ := runWifi(scWifiMobileOnly(seed, true, true))
		revPlain, _ := runWifi(scWifiMobileOnly(seed, false, true))
		revPlainOK += revPlain.SuccessRate(0, 1<<62) / seeds
		plainR += retriedShare(plain) / seeds
		hintR += retriedShare(hint) / seeds
		plainOK += plain.SuccessRate(0, 1<<62) / seeds
		hintOK += hint.SuccessRate(0, 1<<62) / seeds
		revOK += rev.SuccessRate(0, 1<<62) / seeds
	}
	t.Logf("retried: plain %.4f, hinted %.4f; served: plain %.4f, hinted %.4f; only the labelled work: %.4f (unlabelled %.4f)", plainR, hintR, plainOK, hintOK, revOK, revPlainOK)
	if hintR > plainR/2 {
		t.Errorf("hint left %.4f of flows retried (plain %.4f): want at most half", hintR, plainR)
	}
	if hintOK < plainOK {
		t.Errorf("hint served %.4f < plain %.4f", hintOK, plainOK)
	}
	if revOK < revPlainOK-0.01 {
		t.Errorf("with only the labelled paths working, served %.4f (unlabelled %.4f): the hint must not shut them out", revOK, revPlainOK)
	}
}
