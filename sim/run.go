package sim

import (
	"container/heap"
	"math/rand/v2"

	"github.com/tsyrenov1987/farvater-core/brain"
)

// Policy is what the runner drives: farvater-core or the baseline.
type Policy interface {
	Name() string
	Pick(now int64, dst string, class brain.DstClass) brain.Decision
	Observe(r brain.Receipt)
}

// FlowRecord is the user-visible outcome of one flow.
type FlowRecord struct {
	ID       int
	StartMs  int64
	EndMs    int64
	Path     string
	Success  bool
	Dead     bool
	Bytes    int64
	Retried  bool
	Explore  bool
	Reason   string
	WaitedMs int64 // governor delay
}

// Dial is one connection attempt, as an observer of the client sees it.
type Dial struct {
	At, EndAt int64 // when it started; when it answered or the client gave up
	Path      string
	OK        bool // served the flow (no silence, reset or stall)
	Explore   bool
}

// Result is everything a run produced.
type Result struct {
	Policy          string
	Records         []FlowRecord
	Dials           []Dial
	Receipts        int
	MidFlowSwitches int
	Net             *Network
	Picks           map[string][]int64
}

// SuccessRate is the share of live-destination flows started in [fromMs, toMs) that were served.
func (r Result) SuccessRate(fromMs, toMs int64) float64 {
	n, ok := 0, 0
	for _, f := range r.Records {
		if f.Dead || f.StartMs < fromMs || f.StartMs >= toMs {
			continue
		}
		n++
		if f.Success {
			ok++
		}
	}
	if n == 0 {
		return 0
	}
	return float64(ok) / float64(n)
}

// ShareByPath is the share of flows (by final path) per path.
func (r Result) ShareByPath() map[string]float64 {
	m := map[string]float64{}
	for _, f := range r.Records {
		m[f.Path]++
	}
	for k := range m {
		m[k] /= float64(len(r.Records))
	}
	return m
}

// MaxGapMs is the longest interval without a pick on the path, from 0 to endMs.
func (r Result) MaxGapMs(path string, endMs int64) int64 {
	ts := r.Picks[path]
	prev, gap := int64(0), int64(0)
	for _, t := range ts {
		if t-prev > gap {
			gap = t - prev
		}
		prev = t
	}
	if endMs-prev > gap {
		gap = endMs - prev
	}
	return gap
}

type recHeap []brain.Receipt

func (h recHeap) Len() int           { return len(h) }
func (h recHeap) Less(i, j int) bool { return h[i].AtMs < h[j].AtMs }
func (h recHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *recHeap) Push(x any)        { *h = append(*h, x.(brain.Receipt)) }
func (h *recHeap) Pop() any          { o := *h; x := o[len(o)-1]; *h = o[:len(o)-1]; return x }

// A reusing path (kilvater) opens one TLS handshake and carries many streams on
// it; a flow handshakes only when none is live, the slots ran out, or the
// connection outlived its life. These bound a connection the way the client does.
const (
	reuseConnLifeMs = int64(20 * 60_000) // 20 minutes
	reuseMaxStreams = 100
)

type reuseConn struct {
	deadAt int64
	left   int
}

// Runner executes flows of a scenario over the modelled paths.
type Runner struct {
	sc    Scenario
	net   *Network
	rng   *rand.Rand
	paths map[string]*PathModel
	conns map[string]*reuseConn
	gov   *brain.Governor
}

// NewRunner prepares a runner; gov may be nil (no handshake pacing, as in the baseline).
func NewRunner(sc Scenario, gov *brain.Governor) *Runner {
	r := &Runner{sc: sc, net: &sc.Net, rng: rand.New(rand.NewPCG(sc.Seed, sc.Seed+1)), paths: map[string]*PathModel{}, conns: map[string]*reuseConn{}, gov: gov}
	r.net.init()
	for i := range sc.Paths {
		p := sc.Paths[i]
		r.paths[p.ID] = &p
	}
	return r
}

// reusing reports whether a live connection on a reusing path can carry a flow
// starting at `at` without a fresh handshake, spending a stream slot when it
// can; otherwise it opens a new connection (the one handshake) and returns false.
func (r *Runner) reusing(id string, at int64) bool {
	c := r.conns[id]
	if c != nil && at < c.deadAt && c.left > 0 {
		c.left--
		return true
	}
	r.conns[id] = &reuseConn{deadAt: at + reuseConnLifeMs, left: reuseMaxStreams - 1}
	return false
}

// Probe implements baseline.Prober: a tiny request that a cut path answers happily.
func (r *Runner) Probe(path string, at int64) (int64, bool) {
	p := r.paths[path]
	if r.net.IsDown(at) {
		return 0, false
	}
	if r.net.Handshake(p.SNI, at) {
		return 0, false
	}
	if r.rng.Float64() < p.WireFailProb {
		return 0, false
	}
	return p.RTTMs, true
}

const stallWindowMs = 4000

func (r *Runner) execute(pathID string, f Flow, startAt, fbTimeout int64) (rec brain.Receipt, success bool, waited int64) {
	p := r.paths[pathID]
	// A reusing path rides a live connection: no handshake, so neither the
	// governor nor the freeze rule sees one.
	reuse := p.Reuses && r.reusing(pathID, startAt)
	rec = brain.Receipt{Path: pathID, Ctx: "sim", WireReadyMs: -1, FirstByteMs: -1, DownAtFail: -1, Dst: f.Dst, DstClass: f.Class, Up: 800}
	hsAt := startAt
	if r.gov != nil && !reuse {
		hsAt = r.gov.Acquire(p.SNI, p.IP, startAt)
	}
	waited = hsAt - startAt
	fail := func() (brain.Receipt, bool, int64) {
		rec.End = brain.EndTimeout
		rec.DurMs = waited + fbTimeout
		rec.AtMs = startAt + rec.DurMs
		return rec, false, waited
	}
	if r.net.IsDown(hsAt) || (!reuse && r.net.Handshake(p.SNI, hsAt)) || r.rng.Float64() < p.WireFailProb || p.WireDeadFrom > 0 && hsAt >= p.WireDeadFrom && (p.WireDeadTo == 0 || hsAt < p.WireDeadTo) {
		if p.Reuses {
			delete(r.conns, pathID) // a broken connection forces a fresh handshake next time
		}
		return fail()
	}
	rec.WireReadyMs = waited + p.RTTMs
	if f.Dead {
		rec.DurMs = rec.WireReadyMs + fbTimeout
		rec.End = brain.EndTimeout
		rec.AtMs = startAt + rec.DurMs
		return rec, false, waited
	}
	if p.BlackholeFrom > 0 && startAt >= p.BlackholeFrom {
		// The path connects but the server is silently black-holed by the DPI.
		rec.End = brain.EndTimeout
		rec.DurMs = rec.WireReadyMs + fbTimeout
		rec.AtMs = startAt + rec.DurMs
		return rec, false, waited
	}
	rec.FirstByteMs = rec.WireReadyMs + p.RTTMs/2 + 5
	if p.ResetAtBytes > 0 && startAt >= p.ResetOnsetMs && f.WantBytes > p.ResetAtBytes {
		// Injected RST after the first byte: active DPI reset mid-stream.
		rec.Down, rec.DownAtFail, rec.Stalls = p.ResetAtBytes, p.ResetAtBytes, 0
		rec.End = brain.EndWireReset
		rec.DurMs = rec.FirstByteMs + p.RTTMs
		rec.AtMs = startAt + rec.DurMs
		return rec, false, waited
	}
	cut := p.CutAtBytes
	if cut > 0 && startAt < p.OnsetMs {
		cut = 0
	}
	if cut > 0 && f.WantBytes > cut {
		rec.Down, rec.DownAtFail, rec.Stalls = cut, cut, 1
		rec.End = brain.EndStallAbandon
		rec.MaxGapMs = stallWindowMs
		rec.DurMs = rec.FirstByteMs + stallWindowMs
		rec.AtMs = startAt + rec.DurMs
		return rec, false, waited
	}
	rec.Down = f.WantBytes
	rec.End = brain.EndRemoteFin
	gp := p.GoodputBps
	if gp <= 0 {
		gp = 2_000_000
	}
	rec.DurMs = rec.FirstByteMs + f.WantBytes*1000/gp
	rec.MaxGapMs = p.RTTMs
	rec.AtMs = startAt + rec.DurMs
	return rec, true, waited
}

// Run drives a policy through the scenario. The brain's governor is used when
// the policy is farvater-core (pass it as gov); the baseline runs without one.
func Run(sc Scenario, pol Policy, gov *brain.Governor) Result {
	return NewRunner(sc, gov).Execute(pol)
}

// Execute drives a policy over this runner's scenario. Flows and connect-stage
// retries are processed as time-ordered events so that every governor call and
// every receipt is observed in causal order.
func (r *Runner) Execute(pol Policy) Result {
	sc := r.sc
	flows := GenerateWorkload(sc.Work, rand.New(rand.NewPCG(sc.Seed^0xabcdef, sc.Seed)))
	res := Result{Policy: pol.Name(), Net: r.net, Picks: map[string][]int64{}}
	pending := &recHeap{}
	retries := &retryHeap{}
	flush := func(upTo int64) {
		for pending.Len() > 0 && (*pending)[0].AtMs <= upTo {
			rc := heap.Pop(pending).(brain.Receipt)
			pol.Observe(rc)
			res.Receipts++
		}
	}
	i := 0
	for i < len(flows) || retries.Len() > 0 {
		if retries.Len() > 0 && (i >= len(flows) || (*retries)[0].at <= flows[i].StartMs) {
			ev := heap.Pop(retries).(retryEvent)
			flush(ev.at)
			rec2, ok2, w2 := r.execute(ev.dec.Secondary, ev.flow, ev.at, ev.dec.StaggerMs)
			rec2.Explore = ev.dec.Explore
			heap.Push(pending, rec2)
			res.Dials = append(res.Dials, Dial{At: ev.at, EndAt: ev.at + rec2.DurMs, Path: ev.dec.Secondary, OK: ok2})
			fr := ev.fr
			fr.Path, fr.Success, fr.Retried = ev.dec.Secondary, ok2, true
			fr.WaitedMs += w2
			fr.EndMs = ev.at + rec2.DurMs
			res.Records = append(res.Records, fr)
			continue
		}
		f := flows[i]
		i++
		flush(f.StartMs)
		d := pol.Pick(f.StartMs, f.Dst, f.Class)
		rec, ok, waited := r.execute(d.Primary, f, f.StartMs, d.StaggerMs)
		rec.Explore = d.Explore
		heap.Push(pending, rec)
		res.Dials = append(res.Dials, Dial{At: f.StartMs, EndAt: f.StartMs + rec.DurMs, Path: d.Primary, OK: ok, Explore: d.Explore})
		res.Picks[d.Primary] = append(res.Picks[d.Primary], f.StartMs)
		fr := FlowRecord{ID: f.ID, StartMs: f.StartMs, Path: d.Primary, Success: ok, Dead: f.Dead, Bytes: f.WantBytes, Explore: d.Explore, Reason: d.Reason, WaitedMs: waited}
		if !rec.FirstByte() && d.Secondary != "" && d.Secondary != d.Primary {
			heap.Push(retries, retryEvent{at: f.StartMs + rec.DurMs, flow: f, dec: d, fr: fr})
			continue
		}
		fr.EndMs = f.StartMs + rec.DurMs
		res.Records = append(res.Records, fr)
	}
	flush(1 << 62)
	return res
}

type retryEvent struct {
	at   int64
	flow Flow
	dec  brain.Decision
	fr   FlowRecord
}

type retryHeap []retryEvent

func (h retryHeap) Len() int           { return len(h) }
func (h retryHeap) Less(i, j int) bool { return h[i].at < h[j].at }
func (h retryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *retryHeap) Push(x any)        { *h = append(*h, x.(retryEvent)) }
func (h *retryHeap) Pop() any          { o := *h; x := o[len(o)-1]; *h = o[:len(o)-1]; return x }

// BrainPolicy adapts a brain to the runner.
type BrainPolicy struct{ B *brain.Brain }

func (p *BrainPolicy) Name() string { return "farvater" }
func (p *BrainPolicy) Pick(now int64, dst string, class brain.DstClass) brain.Decision {
	return p.B.Pick(now, dst, class)
}
func (p *BrainPolicy) Observe(r brain.Receipt) { p.B.Observe(r) }
