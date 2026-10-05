// Package baseline models the latency-based selector that farvater-core replaces:
// a `urltest` group picks the path with the lowest RTT of a tiny probe every
// interval and ignores what real flows experience.
package baseline

import "github.com/tsyrenov1987/farvater-core/brain"

// Prober answers a tiny health-check request over a path.
type Prober interface {
	Probe(path string, atMs int64) (rttMs int64, ok bool)
}

// URLTest is the model.
type URLTest struct {
	Paths       []string
	IntervalMs  int64
	ToleranceMs int64
	prober      Prober
	sel         string
	lastCheck   int64
	checked     bool
	Changes     int
	Checks      int
}

// New returns a urltest model with the usual defaults (3 min, 50 ms tolerance).
func New(paths []string, p Prober) *URLTest {
	return &URLTest{Paths: paths, IntervalMs: 180_000, ToleranceMs: 50, prober: p}
}

func (u *URLTest) Name() string { return "urltest" }

func (u *URLTest) check(now int64) {
	u.Checks++
	u.checked = true
	u.lastCheck = now
	best, bestRTT := "", int64(1<<62)
	selRTT, selOK := int64(0), false
	for i, p := range u.Paths {
		rtt, ok := u.prober.Probe(p, now+int64(i)*5) // all probes fired together: the race
		if !ok {
			continue
		}
		if p == u.sel {
			selRTT, selOK = rtt, true
		}
		if rtt < bestRTT {
			best, bestRTT = p, rtt
		}
	}
	if best == "" {
		return // nothing answered: keep the current selection
	}
	if selOK && selRTT <= bestRTT+u.ToleranceMs {
		return
	}
	if u.sel != "" {
		u.Changes++
	}
	u.sel = best
}

// Pick returns the selected path, re-checking when the interval elapsed.
func (u *URLTest) Pick(now int64, _ string, _ brain.DstClass) brain.Decision {
	if !u.checked || now-u.lastCheck >= u.IntervalMs {
		u.check(now)
	}
	if u.sel == "" {
		u.sel = u.Paths[0]
	}
	return brain.Decision{Primary: u.sel, Reason: "lowest_rtt", StaggerMs: 3000}
}

// Observe ignores receipts: that is the point of the baseline.
func (u *URLTest) Observe(brain.Receipt) {}
