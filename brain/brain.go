package brain

import (
	"fmt"
	"math/rand/v2"
)

// PathInfo identifies a path of the catalogue.
type PathInfo struct{ ID, SNI, IP string }

// Config holds the selection parameters. All numbers are initial hypotheses.
type Config struct {
	HalfLifeMs         int64   // forgetting half-life of receipt evidence
	LeaderDelta        float64 // challenger must beat the leader by this much (posterior mean)
	LeaderMinReceipts  int     // ...with at least this many own receipts in LeaderWindowMs
	LeaderWindowMs     int64
	LeaderStallStrikes int     // consecutive stalls that dethrone the leader
	ExploreShare       float64 // cap on exploration flows inside ExploreWindowMs
	ExploreWindowMs    int64
	FloorMs            int64 // every path gets at least one flow per FloorMs
	FirstByteCapMs     int64 // T_fb cap
	StaggerPadMs       int64 // added to p90 first-byte for the connect-stage retry
}

// DefaultConfig returns the design defaults.
func DefaultConfig() Config {
	return Config{HalfLifeMs: 10 * 60_000, LeaderDelta: 0.15, LeaderMinReceipts: 5, LeaderWindowMs: 15 * 60_000,
		LeaderStallStrikes: 2, ExploreShare: 0.2, ExploreWindowMs: 60_000, FloorMs: 10 * 60_000, FirstByteCapMs: 3000, StaggerPadMs: 300}
}

// Decision is the answer to "which wire for this flow".
type Decision struct {
	Primary   string
	Secondary string // connect-stage retry target ("" = none)
	Explore   bool
	Reason    string
	StaggerMs int64 // no first byte within this → retry over Secondary
}

type pickRec struct {
	at      int64
	explore bool
}

// Brain selects paths by proven delivery.
type Brain struct {
	cfg         Config
	ctx         string
	paths       []PathInfo
	st          map[string]*PathState
	leader      string
	leaderSince int64
	lastPick    map[string]int64
	picks       []pickRec
	started     bool
	Gov         *Governor
	Diag        *Diagnoser
	J           *Journal
	rng         *rand.Rand
	Dropped     int // receipts not counted (network down / quarantined destination)
}

// New creates a brain for one network context.
func New(cfg Config, ctx string, paths []PathInfo, seed uint64) *Brain {
	b := &Brain{cfg: cfg, ctx: ctx, paths: paths, st: map[string]*PathState{}, lastPick: map[string]int64{},
		Gov: NewGovernor(), Diag: NewDiagnoser(paths), J: NewJournal(1000), rng: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))}
	for _, p := range paths {
		b.st[p.ID] = &PathState{}
	}
	return b
}

// SetPrior installs a weak delivery prior for a path (from memory or catalogue).
func (b *Brain) SetPrior(path string, a, bb, weight float64) {
	if s, ok := b.st[path]; ok {
		s.SetDelivPrior(a, bb, weight)
	}
}

// Leader is the current leading path.
func (b *Brain) Leader() string { return b.leader }

// State returns a copy of a path's evidence.
func (b *Brain) State(path string) PathState {
	if s, ok := b.st[path]; ok {
		return *s
	}
	return PathState{}
}

func (b *Brain) available(now int64) []string {
	out := make([]string, 0, len(b.paths))
	for _, p := range b.paths {
		if !b.Diag.Parked(p.ID, now) {
			out = append(out, p.ID)
		}
	}
	if len(out) == 0 {
		for _, p := range b.paths {
			out = append(out, p.ID)
		}
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func (b *Brain) bestBy(avail []string, exclude string, needReceipts bool, now int64) (string, float64) {
	best, bestM := "", -1.0
	for _, p := range avail {
		if p == exclude {
			continue
		}
		s := b.st[p]
		if needReceipts && s.RecentReceipts(now, b.cfg.LeaderWindowMs) < b.cfg.LeaderMinReceipts {
			continue
		}
		if m := s.Mean(); m > bestM {
			best, bestM = p, m
		}
	}
	return best, bestM
}

func (b *Brain) setLeader(p string, now int64, act, why string) {
	if p == "" || p == b.leader {
		return
	}
	b.leader, b.leaderSince = p, now
	b.J.Add(now, act, why, p)
}

func (b *Brain) exploreShare(now int64) float64 {
	i := 0
	for i < len(b.picks) && b.picks[i].at < now-b.cfg.ExploreWindowMs {
		i++
	}
	b.picks = b.picks[i:]
	if len(b.picks) == 0 {
		return 0
	}
	n := 0
	for _, p := range b.picks {
		if p.explore {
			n++
		}
	}
	return float64(n) / float64(len(b.picks))
}

// Pick chooses the wire for a new flow.
func (b *Brain) Pick(now int64, dst string, class DstClass) Decision {
	if !b.started {
		b.started = true
		for _, p := range b.paths {
			b.lastPick[p.ID] = now
		}
	}
	avail := b.available(now)

	if b.leader == "" || !contains(avail, b.leader) {
		l, _ := b.bestBy(avail, "", false, now)
		b.setLeader(l, now, "lead_init", "start: best by prior/memory")
	} else {
		ls := b.st[b.leader]
		if cand, m := b.bestBy(avail, b.leader, true, now); cand != "" && m >= ls.Mean()+b.cfg.LeaderDelta {
			b.setLeader(cand, now, "lead_switch", fmt.Sprintf("posterior %.2f vs %.2f of %s", m, ls.Mean(), b.leader))
		} else if ls.ConsecutiveStalls() >= b.cfg.LeaderStallStrikes {
			if cand, _ := b.bestBy(avail, b.leader, false, now); cand != "" {
				old := b.leader
				b.setLeader(cand, now, "lead_stall", fmt.Sprintf("%d consecutive stalls on %s", ls.ConsecutiveStalls(), old))
				ls.ResetStalls()
			}
		}
	}

	primary, explore, reason := b.leader, false, "leader"
	for _, p := range avail {
		if p == b.leader {
			continue
		}
		if now-b.lastPick[p] >= b.cfg.FloorMs {
			primary, explore, reason = p, true, "explore_floor"
			break
		}
	}
	if !explore && b.exploreShare(now) < b.cfg.ExploreShare {
		bestP, bestV := "", -1.0
		for _, p := range avail {
			if v := b.st[p].Sample(b.rng); v > bestV {
				bestP, bestV = p, v
			}
		}
		if bestP != "" && bestP != b.leader {
			primary, explore, reason = bestP, true, "thompson"
		}
	}
	secondary, _ := b.bestBy(avail, primary, false, now)
	b.lastPick[primary] = now
	b.picks = append(b.picks, pickRec{now, explore})

	stagger := b.st[primary].P90FirstByteMs() + b.cfg.StaggerPadMs
	if stagger > b.cfg.FirstByteCapMs {
		stagger = b.cfg.FirstByteCapMs
	}
	return Decision{Primary: primary, Secondary: secondary, Explore: explore, Reason: reason, StaggerMs: stagger}
}

// Observe folds a receipt into the evidence, after differential diagnosis.
func (b *Brain) Observe(r Receipt) {
	s, ok := b.st[r.Path]
	if !ok {
		return
	}
	now := r.AtMs
	wireOK := r.WireReadyMs >= 0
	b.Diag.NoteWire(r.Path, wireOK, now)
	if !wireOK && b.Diag.NetDown(now) {
		b.Dropped++
		b.J.Add(now, "drop_netdown", "no path connects: not evidence against the path", r.Path)
		return
	}
	if wireOK && !r.FirstByte() && r.Dst != "" {
		if b.Diag.DstQuarantined(r.Dst, now) {
			b.Dropped++
			return
		}
		b.Diag.NoteDst(r.Dst, r.Path, false, now)
	} else if r.FirstByte() {
		b.Diag.NoteDst(r.Dst, r.Path, true, now)
	}
	s.Observe(r, now, b.cfg.HalfLifeMs)
}
