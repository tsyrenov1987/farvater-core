package sim

import "github.com/tsyrenov1987/farvater-core/baseline"

// RunURLTest runs the latency baseline over a scenario (no handshake pacing,
// probes fired together, receipts ignored) and returns the model for inspection.
func RunURLTest(sc Scenario) (Result, *baseline.URLTest) {
	r := NewRunner(sc, nil)
	ids := make([]string, 0, len(sc.Paths))
	for _, p := range sc.Paths {
		ids = append(ids, p.ID)
	}
	u := baseline.New(ids, r)
	return r.Execute(u), u
}
