package brain

import "sort"

// Governor paces new TLS handshakes per SNI and per IP so that neither a
// start-up race nor a page load ever looks like a handshake burst. Slots may
// be queued into the future; a later request must respect those queued slots
// too, so the check looks at every window the new slot would fall into.
type Governor struct {
	SNIMax   int   // handshakes allowed per SNI inside SNIWinMs
	SNIWinMs int64 //
	IPMax    int
	IPWinMs  int64
	perSNI   map[string][]int64
	perIP    map[string][]int64
	tightTil int64
}

// NewGovernor returns the default pacing: ≤2 per SNI per 400 ms, ≤4 per IP per 1 s.
func NewGovernor() *Governor {
	return &Governor{SNIMax: 2, SNIWinMs: 400, IPMax: 4, IPWinMs: 1000, perSNI: map[string][]int64{}, perIP: map[string][]int64{}}
}

// Tighten halves the budgets and doubles the windows until untilMs.
func (g *Governor) Tighten(untilMs int64) { g.tightTil = untilMs }

// Acquire schedules a handshake for sni/ip requested at now and returns the
// earliest slot (≥ now) that keeps every window within budget. The slot is recorded.
func (g *Governor) Acquire(sni, ip string, now int64) int64 {
	n, win := g.SNIMax, g.SNIWinMs
	in, iwin := g.IPMax, g.IPWinMs
	if now < g.tightTil {
		n, win = max(1, n/2), win*2
		in, iwin = max(1, in/2), iwin*2
	}
	g.perSNI[sni] = prune(g.perSNI[sni], now-4*max(win, iwin))
	g.perIP[ip] = prune(g.perIP[ip], now-4*max(win, iwin))
	s, p := g.perSNI[sni], g.perIP[ip]

	cands := []int64{now}
	last := now
	for _, ts := range [][]int64{s, p} {
		for _, t := range ts {
			last = max(last, t)
			for _, c := range []int64{t, t + 1, t + win, t + iwin} {
				if c >= now {
					cands = append(cands, c)
				}
			}
		}
	}
	cands = append(cands, last+max(win, iwin)) // always fits
	sort.Slice(cands, func(i, j int) bool { return cands[i] < cands[j] })
	at := cands[len(cands)-1]
	for _, c := range cands {
		if fits(s, c, n, win) && fits(p, c, in, iwin) {
			at = c
			break
		}
	}
	g.perSNI[sni] = insertSorted(s, at)
	g.perIP[ip] = insertSorted(p, at)
	return at
}

// fits reports whether inserting at keeps every n+1 consecutive slots at least win apart,
// i.e. no window of length win holds more than n slots.
func fits(ts []int64, at int64, n int, win int64) bool {
	m := insertSorted(append([]int64(nil), ts...), at)
	for i := 0; i+n < len(m); i++ {
		if m[i+n]-m[i] < win {
			return false
		}
	}
	return true
}

func prune(ts []int64, before int64) []int64 {
	out := ts[:0]
	for _, t := range ts {
		if t >= before {
			out = append(out, t)
		}
	}
	return out
}

func insertSorted(ts []int64, t int64) []int64 {
	i := sort.Search(len(ts), func(i int) bool { return ts[i] > t })
	ts = append(ts, 0)
	copy(ts[i+1:], ts[i:])
	ts[i] = t
	return ts
}
