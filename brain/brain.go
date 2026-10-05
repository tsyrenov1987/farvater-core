package brain

import (
	"fmt"
	"math/rand/v2"
)

// PathInfo identifies a path of the catalogue.
type PathInfo struct{ ID, SNI, IP, Rail string }

// Config holds the selection parameters. All numbers are initial hypotheses.
type Config struct {
	HalfLifeMs             int64   // forgetting half-life of receipt evidence
	LeaderDelta            float64 // challenger must beat the leader by this much (posterior mean)
	LeaderMinReceipts      int     // ...with at least this many own receipts in LeaderWindowMs
	LeaderWindowMs         int64
	LeaderStallStrikes     int     // consecutive stalls that dethrone the leader
	ExploreShare           float64 // cap on exploration flows inside ExploreWindowMs
	ExploreWindowMs        int64
	FloorMs                int64         // every path gets at least one flow per FloorMs
	FirstByteCapMs         int64         // T_fb cap for the connect-stage stagger
	StaggerPadMs           int64         // added to p90 first-byte for the connect-stage retry
	FirstByteDeadlineCapMs int64         // hard cap on the per-flow abandon-and-migrate deadline
	Breaker                BreakerConfig // anti-TSPU circuit breaker
}

// DefaultConfig returns the design defaults.
func DefaultConfig() Config {
	return Config{HalfLifeMs: 10 * 60_000, LeaderDelta: 0.15, LeaderMinReceipts: 5, LeaderWindowMs: 15 * 60_000,
		LeaderStallStrikes: 2, ExploreShare: 0.2, ExploreWindowMs: 60_000, FloorMs: 10 * 60_000, FirstByteCapMs: 3000, StaggerPadMs: 300,
		FirstByteDeadlineCapMs: 5000, Breaker: DefaultBreakerConfig()}
}

// Decision is the answer to "which wire for this flow".
type Decision struct {
	Primary             string
	Secondary           string // connect-stage retry target ("" = none)
	Explore             bool
	Tertiary            string // storm-mode third, diverse dial ("" = none)
	Reason              string
	StaggerMs           int64 // no first byte within this → start the next dial
	FirstByteDeadlineMs int64 // no first byte within this → abandon and migrate the flow
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
	Breaker     *Breaker
	J           *Journal
	rng         *rand.Rand
	Dropped     int // receipts not counted (network down / quarantined destination)
}

// New creates a brain for one network context.
func New(cfg Config, ctx string, paths []PathInfo, seed uint64) *Brain {
	b := &Brain{cfg: cfg, ctx: ctx, paths: paths, st: map[string]*PathState{}, lastPick: map[string]int64{},
		Gov: NewGovernor(), Diag: NewDiagnoser(paths), Breaker: NewBreaker(cfg.Breaker), J: NewJournal(1000), rng: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))}
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
		if !b.Diag.Parked(p.ID, now) && !b.Breaker.Tripped(p.ID, now) {
			out = append(out, p.ID)
		}
	}
	if len(out) == 0 {
		// Never narrow to nothing: if the breaker and the freeze guard would
		// silence the whole fleet, fall back to everything and let delivery
		// measurement re-sort it. A rail is avoided, never removed.
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

// diversity scores how mechanically unlike two paths are: a different protocol
// rail, a different SNI and a different server IP each count. A DPI block tends
// to hit one of those axes, so the escape route should maximise distance from
// the rail that just failed.
func diversity(a, b PathInfo) int {
	d := 0
	if a.Rail != b.Rail {
		d++
	}
	if a.SNI != b.SNI {
		d++
	}
	if a.IP != b.IP {
		d++
	}
	return d
}

func (b *Brain) info(id string) PathInfo {
	for _, p := range b.paths {
		if p.ID == id {
			return p
		}
	}
	return PathInfo{ID: id}
}

// bestEscape picks the connect-stage / storm runner-up: mostly by delivery, but
// biased toward a rail unlike `from`, so a shared-SNI or same-IP sibling of a
// failing primary is not chosen as its own backup.
func (b *Brain) bestEscape(avail, exclude []string, from PathInfo, now int64) string {
	bestP, bestV := "", -1.0
	for _, p := range avail {
		if contains(exclude, p) {
			continue
		}
		s := b.st[p]
		score := 0.85*s.Mean() + 0.15*float64(diversity(b.info(p), from))/3
		if score > bestV {
			bestP, bestV = p, score
		}
	}
	return bestP
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
	storm := b.Breaker.Storm(now)
	exploreCap := b.cfg.ExploreShare
	if storm {
		exploreCap = b.Breaker.cfg.StormExplore
	}
	if !explore && b.exploreShare(now) < exploreCap {
		bestP, bestV := "", -1.0
		for _, p := range avail {
			if v := b.st[p].Sample(b.rng); v > bestV {
				bestP, bestV = p, v
			}
		}
		if bestP != "" && bestP != b.leader {
			primary, explore, reason = bestP, true, "thompson"
			if storm {
				reason = "storm_probe"
			}
		}
	}
	from := b.info(primary)
	secondary := b.bestEscape(avail, []string{primary}, from, now)
	tertiary := ""
	if storm && b.Breaker.cfg.StormFanout {
		tertiary = b.bestEscape(avail, []string{primary, secondary}, from, now)
	}
	b.lastPick[primary] = now
	b.picks = append(b.picks, pickRec{now, explore})

	stagger := b.st[primary].P90FirstByteMs() + b.cfg.StaggerPadMs
	if stagger > b.cfg.FirstByteCapMs {
		stagger = b.cfg.FirstByteCapMs
	}
	deadline := b.st[primary].P90FirstByteMs()*3 + b.cfg.StaggerPadMs
	if deadline < 1500 {
		deadline = 1500
	}
	if cap := b.cfg.FirstByteDeadlineCapMs; cap > 0 && deadline > cap {
		deadline = cap
	}
	return Decision{Primary: primary, Secondary: secondary, Tertiary: tertiary, Explore: explore, Reason: reason, StaggerMs: stagger, FirstByteDeadlineMs: deadline}
}

// Observe folds a receipt into the evidence, after differential diagnosis.
func (b *Brain) Observe(r Receipt) {
	s, ok := b.st[r.Path]
	if !ok {
		return
	}
	now := r.AtMs
	if r.SleptMs >= SleepGraceMs {
		// A phone asleep loses its flows whatever the path: NAT mappings
		// expire and the radio goes quiet.
		b.Dropped++
		b.J.Add(now, "drop_sleep", "the device slept during the flow: not evidence against the path", r.Path)
		return
	}
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
	if tripped, sig := b.Breaker.Note(r, now); tripped {
		if r.Path == b.leader {
			old := b.leader
			b.leader = "" // force re-election on the next Pick, bypassing hysteresis
			b.J.Add(now, "lead_trip", "breaker: "+sig.String()+" on leader", old)
		} else {
			b.J.Add(now, "trip", "breaker: "+sig.String(), r.Path)
		}
	}
}
