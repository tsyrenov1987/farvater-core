// Package fleet drives a brain with a large catalogue through a spell of
// network trouble, sweeps included, and measures what the user's flows got.
package fleet

import (
	"container/heap"
	"fmt"
	"math/rand/v2"
	"os"
	"testing"

	"github.com/tsyrenov1987/farvater-core/brain"
)

type ev struct {
	at int64
	fn func()
}
type evq []ev

func (h evq) Len() int           { return len(h) }
func (h evq) Less(i, j int) bool { return h[i].at < h[j].at }
func (h evq) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *evq) Push(x any)        { *h = append(*h, x.(ev)) }
func (h *evq) Pop() any          { o := *h; x := o[len(o)-1]; *h = o[:len(o)-1]; return x }

type fleet struct{ good, mid, junk int }

type outcome struct {
	served, flows int
	waitMs        int64 // dial time lost before the dial that served
	leadGood      int   // ticks the leader was a good path
	ticks         int
	leads         int
}

const (
	hangMs  = 3000
	connMs  = 150
	probeMs = 600
)

// run: warmMs of calm, troubleMs when every dial succeeds with its odds times
// troubleFactor, then calm again until endMs. It returns the outcome per phase.
func run(f fleet, seed uint64, warmMs, troubleMs, endMs int64, trouble func(rail string) float64, cfg brain.Config) ([3]outcome, []outcome) {
	var paths []brain.PathInfo
	odds := map[string]float64{}
	railOf := map[string]string{}
	rails := []string{"reality", "xhttp", "grpc", "kilvater", "hy2", "ws"}
	add := func(n int, class string, p float64) {
		for i := 0; i < n; i++ {
			id := fmt.Sprintf("%s%d", class, i)
			k := len(paths)
			paths = append(paths, brain.PathInfo{ID: id, SNI: fmt.Sprintf("s%d.ex", k), IP: fmt.Sprintf("10.0.%d.%d", k/200, k%200+1), Rail: rails[k%len(rails)]})
			odds[id] = p
			railOf[id] = rails[k%len(rails)]
		}
	}
	add(f.good, "good", 0.97)
	add(f.mid, "mid", 0.5)
	add(f.junk, "junk", 0.05)
	rng := rand.New(rand.NewPCG(seed, seed+1))
	rng.Shuffle(len(paths), func(i, j int) { paths[i], paths[j] = paths[j], paths[i] })
	br := brain.New(cfg, "cell:t", paths, seed)
	q := &evq{}
	now := int64(1000)
	at := func(t int64, fn func()) { heap.Push(q, ev{t, fn}) }
	phase := func(t int64) int {
		switch {
		case t < warmMs:
			return 0
		case t < warmMs+troubleMs:
			return 1
		}
		return 2
	}
	dial := func(p string, t int64) bool {
		o := odds[p]
		if phase(t) == 1 {
			o *= trouble(railOf[p])
		}
		return rng.Float64() < o
	}
	receipt := func(p string, start int64, okk bool) {
		r := brain.Receipt{Path: p, Ctx: "cell:t", WireReadyMs: -1, FirstByteMs: -1, DownAtFail: -1, Dst: "h", DstClass: brain.DstTLS443, Up: 800}
		if okk {
			r.WireReadyMs, r.FirstByteMs, r.AnswerMs, r.Down, r.BusyDown, r.BusyMs, r.DurMs, r.End = connMs, connMs+50, connMs+50, 64<<10, 64<<10, 200, 400, brain.EndRemoteFin
			at(start+connMs+50, func() { br.NoteAnswered(p, start, start+connMs+50) })
		} else {
			r.DurMs, r.End = hangMs, brain.EndTimeout
		}
		r.AtMs = start + r.DurMs
		at(r.AtMs, func() { br.NoteQuiet(r); br.Observe(r) })
	}
	var out [3]outcome
	buckets := make([]outcome, (endMs-warmMs)/30_000+1)
	var flow func(t int64)
	flow = func(t int64) {
		d := br.Pick(t, "h", brain.DstTLS443)
		ph := phase(t)
		out[ph].flows++
		var bk *outcome
		if t >= warmMs {
			bk = &buckets[(t-warmMs)/30_000]
			bk.flows++
		}
		order := []string{d.Primary}
		for _, p := range []string{d.Secondary, d.Tertiary} {
			if p != "" && p != order[0] && (len(order) < 2 || p != order[1]) {
				order = append(order, p)
			}
		}
		for i, p := range order {
			start := t + int64(i)*d.StaggerMs
			okk := dial(p, start)
			receipt(p, start, okk)
			if okk {
				out[ph].served++
				out[ph].waitMs += start - t
				if bk != nil {
					bk.served++
					bk.waitMs += start - t
				}
				break
			}
		}
	}
	lastLead := ""
	for t := now; t < endMs; t += 100 {
		for q.Len() > 0 && (*q)[0].at <= t {
			heap.Pop(q).(ev).fn()
		}
		if t%500 == 0 {
			flow(t)
		}
		for _, p := range br.SweepDue(t) {
			okk := dial(p, t)
			if os.Getenv("FLEET_TRACE") != "" && t >= warmMs && t < warmMs+45_000 {
				fmt.Printf("%6.1f   probe %s %s %v\n", float64(t-warmMs)/1000, p, railOf[p], okk)
			}
			receipt(p, t, okk)
			if okk {
				at(t+probeMs, func() { br.Swept(p, 256<<10, probeMs, true, t+probeMs) })
			} else {
				at(t+hangMs, func() { br.Swept(p, 0, hangMs, false, t+hangMs) })
			}
		}
		br.SweepCheck(t)
		ph := phase(t)
		out[ph].ticks++
		if l := br.Leader(); l != "" {
			if len(l) > 4 && l[:4] == "good" {
				out[ph].leadGood++
			}
			if l != lastLead {
				out[ph].leads++
				lastLead = l
			}
		}
	}
	if os.Getenv("FLEET_TRACE") != "" {
		for _, e := range br.J.Entries() {
			if e.AtMs >= warmMs-2000 && e.AtMs < warmMs+45_000 && e.Act != "pick" {
				fmt.Printf("%6.1f %-12s %-10s %s\n", float64(e.AtMs-warmMs)/1000, e.Act, e.Path, e.Why)
			}
		}
	}
	return out, buckets
}

func TestFleetSizeUnderTrouble(t *testing.T) {
	if os.Getenv("FLEET") == "" {
		t.Skip("measurement: set FLEET=1")
	}
	scen := map[string]func(string) float64{
		"all x0.07": func(string) float64 { return 0.07 },
		"only hy2 live": func(r string) float64 {
			if r == "hy2" {
				return 1
			}
			return 0.03
		},
	}
	for _, name := range []string{"all x0.07", "only hy2 live"} {
		for _, f := range []fleet{{8, 4, 4}, {8, 30, 30}, {8, 60, 62}} {
			const seeds = 20
			var bs []outcome
			for s := uint64(1); s <= seeds; s++ {
				_, b := run(f, s, 10*60_000, 5*60_000, 20*60_000, scen[name], brain.DefaultConfig())
				if bs == nil {
					bs = make([]outcome, len(b))
				}
				for i := range b {
					bs[i].served += b[i].served
					bs[i].flows += b[i].flows
					bs[i].waitMs += b[i].waitMs
				}
			}
			line := ""
			for i := 0; i < 14 && i < len(bs); i++ {
				line += fmt.Sprintf(" %3.0f", 100*float64(bs[i].served)/float64(max(bs[i].flows, 1)))
			}
			t.Logf("%-14s fleet %3d: served%% per 30 s (trouble = first 10):%s", name, f.good+f.mid+f.junk, line)
		}
	}
}

func TestFleetTrace(t *testing.T) {
	if os.Getenv("FLEET_TRACE") == "" {
		t.Skip()
	}
	_, b := run(fleet{8, 60, 62}, 3, 30*60_000, 5*60_000, 31*60_000, func(r string) float64 {
		if r == "hy2" {
			return 1
		}
		return 0.03
	}, brain.DefaultConfig())
	t.Logf("first bucket %d/%d", b[0].served, b[0].flows)
}
