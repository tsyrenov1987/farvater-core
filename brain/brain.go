package brain

import (
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
)

// PathInfo identifies a path of the catalogue. White: the catalogue says the
// path enters through an allow-listed address. Net: the network the catalogue
// says the path is meant for ("cell", "wifi"; "" or "any": every network).
type PathInfo struct {
	ID, SNI, IP, Rail string
	White             bool
	Net               string
	// NotHTTP: the path's traffic looks like no HTTP (Hysteria 2 under
	// Salamander noise). Such a path stays in the fan and takes flows on proven
	// delivery, but never stands in for a failing one: a flow that fails is
	// never retried over it, so a block does not light it up next.
	NotHTTP bool
}

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

	// A leader that delivers, but slowly (shaped), is caught by goodput: its
	// fresh goodput under SlowBps sends up to SpeedProbeShare of flows to the
	// paths with no fresh goodput of their own, and one measured FasterFactor
	// times faster takes the lead, unless its delivery is proven worse.
	// Once SpeedProbeMax other paths have a fresh goodput and none is faster,
	// the network is likely slow, not the leader's path: the rest are probed
	// only within the ordinary ExploreShare, which costs nothing extra. Not
	// stopping matters where a censor shapes all but a few paths.
	SlowBps         float64 // bytes per second
	FasterFactor    float64
	SpeedProbeShare float64
	SpeedProbeMax   int
	GoodputFreshMs  int64

	// A leader that delivers, but answers late (a path with long round
	// trips), is caught by its answer time (Receipt.AnswerMs): a path that
	// answers LagFactor times and LagGapMs sooner takes the lead, unless its
	// delivery is proven worse. A median over LagMs also sends flows to the
	// paths with no answer time yet, as speed probes do.
	LagMs     int64
	LagFactor float64
	LagGapMs  int64

	// DemoteHoldMs: a leader dethroned for what it did (stalls, slowness, a
	// breaker trip) is not handed the lead back by the posterior rule for this
	// long. Its long record of delivery predates the damage and would
	// outweigh the few receipts of the path that took over.
	DemoteHoldMs int64

	// A leader in doubt has the paths swept (sweep.go): up to SweepMax of
	// them get a volume probe at once, at most once per SweepMs (0: never).
	// SweepAlways sweeps every SweepMs, doubt or not.
	SweepMs     int64
	SweepMax    int
	SweepAlways bool
}

// DefaultConfig returns the design defaults.
func DefaultConfig() Config {
	return Config{HalfLifeMs: 10 * 60_000, LeaderDelta: 0.15, LeaderMinReceipts: 5, LeaderWindowMs: 15 * 60_000,
		LeaderStallStrikes: 2, ExploreShare: 0.1, ExploreWindowMs: 60_000, FloorMs: 10 * 60_000, FirstByteCapMs: 3000, StaggerPadMs: 300,
		FirstByteDeadlineCapMs: 5000, Breaker: DefaultBreakerConfig(),
		SlowBps: 128 * 1024, FasterFactor: 3, SpeedProbeShare: 0.3, SpeedProbeMax: 4, GoodputFreshMs: 10 * 60_000,
		LagMs: 300, LagFactor: 2, LagGapMs: 250,
		DemoteHoldMs: 2 * 60_000, SweepMs: 15_000, SweepMax: 8}
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
	Dropped     int   // receipts not counted (network down / quarantined destination)
	Drops       Drops // Dropped by why

	saved      map[string]ctxState         // networks left this session
	mem        *Memory                     // what earlier sessions learned (nil: none)
	priors     map[string]map[string]Prior // the catalogue's, per network
	switchedAt int64                       // last network change: flows begun before it are not evidence
	blockedAt  int64                       // the system blocked the app's network (Blocked); 0: it has not
	silent     map[string]bool             // restricted network: paths silent when it was entered
	back       map[string]bool             // ...and those of them that connected since
	upAt       int64                       // an allow-listed site last answered directly
	upSeen     bool
	asleep     map[string]bool  // paths whose transport is down (Sleep)
	demoted    map[string]int64 // when a path was dethroned for what it did
	doubtAt    int64            // when the leader last tripped or stalled out
	sweptAt    int64            // when the last sweep began
	sw         *sweepRun
	slowAt     []int64 // when flows on the leader were found held back (NoteSlow)
	raceLost   int     // connect races the leader lost in a row (NoteRace)
	raceDoubt  int64   // when they reached two; 0 once it wins one
	askedAt    int64   // the leader's first flow it has not answered since; 0: none

	// when flows on the leader were left unanswered (NoteUnanswered), and when
	// a path lost a sweep without delivering its probe, until it leads again
	unheardAt []int64
	probeLost map[string]int64
}

// New creates a brain for one network context.
func New(cfg Config, ctx string, paths []PathInfo, seed uint64) *Brain {
	b := &Brain{cfg: cfg, ctx: ctx, paths: paths, st: map[string]*PathState{}, lastPick: map[string]int64{},
		Gov: NewGovernor(), Diag: NewDiagnoser(paths), Breaker: NewBreaker(cfg.Breaker), J: NewJournal(1000), rng: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)),
		saved: map[string]ctxState{}, switchedAt: math.MinInt64, asleep: map[string]bool{}, demoted: map[string]int64{}, probeLost: map[string]int64{}}
	for _, p := range paths {
		b.st[p.ID] = &PathState{}
	}
	return b
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

// Sleep takes a path out of the fan until Wake: its transport is down (a
// path the app hosts and has not brought up). It is neither picked nor tried,
// and with no dials its silence says nothing about the network.
func (b *Brain) Sleep(path string, now int64) {
	if b.asleep[path] {
		return
	}
	b.asleep[path] = true
	b.J.Add(now, "sleep", "its transport is down", path)
}

// Wake puts a sleeping path back in the fan.
func (b *Brain) Wake(path string, now int64) {
	if !b.asleep[path] {
		return
	}
	delete(b.asleep, path)
	b.J.Add(now, "wake", "its transport is up", path)
}

// Asleep reports whether a path is out of the fan (see Sleep).
func (b *Brain) Asleep(path string) bool { return b.asleep[path] }

// NetDown suspects the local network: ≥2 distinct paths failed at the wire
// inside the diagnoser's window and nothing connected there. Sleeping paths
// cannot fail, so with fewer than two awake every awake one failing is
// enough; otherwise a sleeping path would never be wanted (see Switchboard.Hosted).
func (b *Brain) NetDown(now int64) bool {
	need := 2
	if len(b.asleep) > 0 {
		need = max(1, min(2, len(b.paths)-len(b.asleep)))
	}
	return b.Diag.NetDown(now, need)
}

func (b *Brain) available(now int64) []string {
	out := make([]string, 0, len(b.paths))
	// In a restricted network a path entering through an allow-listed address
	// is the one meant to pass: a trip earned while the lists still held it
	// back does not keep it out once they let it through.
	white := b.Restricted()
	for _, p := range b.paths {
		if !b.asleep[p.ID] && !b.Diag.Parked(p.ID, now) && (!b.Breaker.Tripped(p.ID, now) || white && p.White) {
			out = append(out, p.ID)
		}
	}
	if len(out) == 0 {
		// Never narrow to nothing: if the breaker and the freeze guard would
		// silence the whole fleet, fall back to everything awake and let
		// delivery measurement re-sort it. A rail is avoided, never removed.
		for _, p := range b.paths {
			if !b.asleep[p.ID] {
				out = append(out, p.ID)
			}
		}
	}
	return out
}

// soonestFree returns, when the breaker has tripped every available path, the
// one whose cooldown ends first: the path that failed longest ago, not the one
// with the best history that failed a moment ago. "" while any path is free.
func (b *Brain) soonestFree(avail []string, now int64) string {
	best, left := "", int64(-1)
	for _, p := range avail {
		l := b.Breaker.TrippedLeftMs(p, now)
		if l == 0 {
			return ""
		}
		if left < 0 || l < left {
			best, left = p, l
		}
	}
	return best
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
		if contains(exclude, p) || b.info(p).NotHTTP {
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

// slowLeader reports the leader's fresh goodput when it is under SlowBps.
func (b *Brain) slowLeader(now int64) (float64, bool) {
	if b.leader == "" || b.cfg.SlowBps <= 0 {
		return 0, false
	}
	bps, n, fresh := b.st[b.leader].Goodput(now, b.cfg.GoodputFreshMs)
	return bps, fresh && n >= 2 && bps < b.cfg.SlowBps
}

// lagSamples is how many answers tell a path's answer time.
const lagSamples = 3

// laggyLeader returns the leader's median answer time and whether it is over
// LagMs, on enough fresh samples to tell.
func (b *Brain) laggyLeader(now int64) (int64, bool) {
	if b.leader == "" || b.cfg.LagMs <= 0 {
		return 0, false
	}
	ms, n := b.st[b.leader].Answer(now, b.cfg.GoodputFreshMs)
	return ms, n >= 5 && ms > b.cfg.LagMs
}

// knownPoor reports whether p's own fresh measure puts it under SlowBps or
// over LagMs. Exploring it again before the measure goes stale (the floor
// still does, every FloorMs) learns nothing new.
func (b *Brain) knownPoor(p string, now int64) bool {
	s := b.st[p]
	if bps, _, fresh := s.Goodput(now, b.cfg.GoodputFreshMs); fresh && b.cfg.SlowBps > 0 && bps < b.cfg.SlowBps {
		return true
	}
	ms, n := s.Answer(now, b.cfg.GoodputFreshMs)
	return b.cfg.LagMs > 0 && n >= lagSamples && ms > b.cfg.LagMs
}

// speedProbe picks, while the leader is slow or answers late, a path whose
// goodput or answer time is not known yet: by a Thompson draw, biased toward
// a path unlike the leader, as shaping goes by address, name or protocol. ""
// when there is none. share is the explore share it may take:
// SpeedProbeShare, or ExploreShare once SpeedProbeMax paths are measured
// already.
func (b *Brain) speedProbe(avail []string, now int64) (p string, share float64, why string) {
	_, slow := b.slowLeader(now)
	_, lag := b.laggyLeader(now)
	if !slow && !lag {
		return "", 0, ""
	}
	lead := b.info(b.leader)
	bestP, bestV, measured := "", -1.0, 0
	for _, p := range avail {
		if p == b.leader || b.probing(p) {
			continue
		}
		_, _, fresh := b.st[p].Goodput(now, b.cfg.GoodputFreshMs)
		_, n := b.st[p].Answer(now, b.cfg.GoodputFreshMs)
		if (!slow || fresh) && (!lag || n >= lagSamples) {
			measured++
			continue
		}
		if v := 0.85*b.st[p].Sample(b.rng) + 0.15*float64(diversity(b.info(p), lead))/3; v > bestV {
			bestP, bestV = p, v
		}
	}
	why = "speed_probe"
	if !slow {
		why = "lag_probe"
	}
	if b.cfg.SpeedProbeMax > 0 && measured >= b.cfg.SpeedProbeMax {
		return bestP, b.cfg.ExploreShare, why
	}
	return bestP, b.cfg.SpeedProbeShare, why
}

// NoteGoodput takes a running flow's goodput, sent once it has carried
// BigBytes: a shaped download takes minutes to end, and its receipt with it.
// A flow begun on a network the device has left says nothing about this one.
func (b *Brain) NoteGoodput(path string, busyDown, busyMs, startMs, now int64) {
	if s, ok := b.st[path]; ok && busyDown >= BigBytes && startMs >= b.switchedAt {
		s.noteGoodput(busyDown, busyMs, now)
		b.measured(path, now)
	}
}

// measured hands the lead of a slow or late leader at once to path, just
// measured faster or quicker, rather than at the next Pick: on a slow leader
// new flows are rare, as each takes minutes.
func (b *Brain) measured(path string, now int64) {
	if path == b.leader || b.leader == "" {
		return
	}
	avail := b.available(now)
	if cand, why := b.faster(avail, now); cand == path && cand != "" {
		b.demoted[b.leader] = now
		b.setLeader(cand, now, "lead_slow", why)
	} else if cand, why := b.quicker(avail, now); cand == path && cand != "" {
		b.demoted[b.leader] = now
		b.setLeader(cand, now, "lead_lag", why)
	}
}

// faster finds, for a slow leader, the fastest path measured FasterFactor
// times faster that has no failed delivery to its name lately or delivers
// within LeaderDelta of the leader: one fast download is enough to win when
// nothing speaks against the path. A leader dethroned lately is not handed
// the lead back.
func (b *Brain) faster(avail []string, now int64) (string, string) {
	lead, slow := b.slowLeader(now)
	if !slow {
		return "", ""
	}
	ls := b.st[b.leader]
	best, bestBps := "", lead*b.cfg.FasterFactor
	for _, p := range avail {
		if p == b.leader || b.held(p, now) {
			continue
		}
		s := b.st[p]
		bps, _, fresh := s.Goodput(now, b.cfg.GoodputFreshMs)
		if fresh && bps >= bestBps && (s.evDelivB < 0.5 || s.DelivMean() >= ls.DelivMean()-b.cfg.LeaderDelta) {
			best, bestBps = p, bps
		}
	}
	if best == "" {
		return "", ""
	}
	return best, fmt.Sprintf("goodput %.0f KB/s vs %.0f KB/s on %s", bestBps/1024, lead/1024, b.leader)
}

// quicker finds, for a leader that answers late, the path answering soonest
// (on lagSamples answers at least), LagFactor times and LagGapMs sooner than
// the leader, not measured much slower than it, with no failed delivery to
// its name lately or delivering within LeaderDelta of the leader.
func (b *Brain) quicker(avail []string, now int64) (string, string) {
	if b.leader == "" || b.cfg.LagFactor <= 0 {
		return "", ""
	}
	ls := b.st[b.leader]
	lead, ln := ls.Answer(now, b.cfg.GoodputFreshMs)
	if ln < 5 {
		return "", ""
	}
	// A leader measured slow carries the load: on a transport that puts all
	// of a path's flows on one connection its answers queue behind its own
	// downloads, while an idle path, shaped alike, answers at once. It is
	// left for a path measured not slow (faster), not on answer time alone.
	_, slow := b.slowLeader(now)
	best, bestMs := "", int64(0)
	for _, p := range avail {
		if p == b.leader || b.held(p, now) || b.muchSlower(p, now) {
			continue
		}
		s := b.st[p]
		if slow {
			if bps, _, fresh := s.Goodput(now, b.cfg.GoodputFreshMs); !fresh || bps < b.cfg.SlowBps {
				continue
			}
		}
		ms, n := s.Answer(now, b.cfg.GoodputFreshMs)
		if n < lagSamples || float64(ms)*b.cfg.LagFactor > float64(lead) || lead-ms < b.cfg.LagGapMs {
			continue
		}
		if (best == "" || ms < bestMs) && (s.evDelivB < 0.5 || s.DelivMean() >= ls.DelivMean()-b.cfg.LeaderDelta) {
			best, bestMs = p, ms
		}
	}
	if best == "" {
		return "", ""
	}
	return best, fmt.Sprintf("answers in %d ms vs %d ms on %s", bestMs, lead, b.leader)
}

// muchLaggier reports whether path p answers LagFactor times and LagGapMs
// later than the leader: the posterior rule does not hand it the lead back.
func (b *Brain) muchLaggier(p string, now int64) bool {
	if b.leader == "" || b.cfg.LagFactor <= 0 {
		return false
	}
	lead, ln := b.st[b.leader].Answer(now, b.cfg.GoodputFreshMs)
	ms, n := b.st[p].Answer(now, b.cfg.GoodputFreshMs)
	return ln >= 2 && n >= 2 && float64(lead)*b.cfg.LagFactor <= float64(ms) && ms-lead >= b.cfg.LagGapMs
}

// held reports whether p was dethroned within DemoteHoldMs.
func (b *Brain) held(p string, now int64) bool {
	at, ok := b.demoted[p]
	return ok && now-at < b.cfg.DemoteHoldMs
}

// muchSlower reports whether path p is measured FasterFactor times slower
// than the leader: its longer record of delivery does not make it the leader
// a slow one was just replaced by.
func (b *Brain) muchSlower(p string, now int64) bool {
	if b.leader == "" || b.cfg.FasterFactor <= 0 {
		return false
	}
	lead, _, lf := b.st[b.leader].Goodput(now, b.cfg.GoodputFreshMs)
	bps, _, pf := b.st[p].Goodput(now, b.cfg.GoodputFreshMs)
	return lf && pf && bps*b.cfg.FasterFactor <= lead
}

func (b *Brain) setLeader(p string, now int64, act, why string) {
	if p == "" || p == b.leader {
		return
	}
	b.leader, b.leaderSince = p, now
	b.raceLost, b.raceDoubt, b.askedAt = 0, 0, 0
	delete(b.probeLost, p)
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

// LeadFreshMs: a path whose flows got an answer within this long gets through
// now. A leader the breaker took away goes to such a path, the one that
// answers quickest: when the leader goes dark the others often go dark with
// it (allow lists, a block by protocol or address), and a long record is no
// evidence that a path still gets through.
const LeadFreshMs = 10000

// answeredNow returns, of the available paths answered within LeadFreshMs of
// now, the one whose answers come quickest (one with no answer time known
// after those with one, the latest answered first); "" when none answered.
func (b *Brain) answeredNow(avail []string, now int64) string {
	best, bestMs, bestAt := "", int64(-1), int64(0)
	for _, p := range avail {
		s := b.st[p]
		if s.AnsweredAt == 0 || s.AnsweredAt < now-LeadFreshMs {
			continue
		}
		ms, n := s.Answer(now, b.cfg.GoodputFreshMs)
		if n == 0 {
			ms = -1
		}
		switch {
		case best == "",
			ms >= 0 && (bestMs < 0 || ms < bestMs),
			ms < 0 && bestMs < 0 && s.AnsweredAt > bestAt:
			best, bestMs, bestAt = p, ms, s.AnsweredAt
		}
	}
	return best
}

// NoteAnswered takes a running flow's first answer: a keep-alive connection
// ends, and its receipt with it, long after its path proved it gets through.
func (b *Brain) NoteAnswered(path string, startMs, now int64) {
	if s, ok := b.st[path]; ok && startMs >= b.switchedAt {
		s.AnsweredAt = max(s.AnsweredAt, now)
	}
}

// leaderAnswers reports whether the leader got an answer since it took the
// lead, within LeadFreshMs: in a storm it is the path that still delivers,
// and wide exploration would only carry flows to the paths that do not.
func (b *Brain) leaderAnswers(now int64) bool {
	s := b.st[b.leader]
	return s != nil && s.AnsweredAt >= b.leaderSince && s.AnsweredAt >= now-LeadFreshMs
}

// leaderUnheard reports whether the leader has left a flow unanswered for
// LeadFreshMs. A leader nobody asked is in no doubt: when the app goes quiet
// for a minute (a reel plays, two downloads hold every connection) no path
// answers anything.
func (b *Brain) leaderUnheard(now int64) bool {
	s := b.st[b.leader]
	return s == nil || b.askedAt > s.AnsweredAt && now-b.askedAt >= LeadFreshMs
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
	if len(avail) == 0 {
		return Decision{Reason: "asleep"} // no path has its transport up
	}

	if b.leader == "" || !contains(avail, b.leader) {
		l, _ := b.bestBy(avail, "", false, now)
		why := "start: best by prior/memory"
		if p := b.answeredNow(avail, now); p != "" {
			l, why = p, "answers now"
		}
		if s := b.soonestFree(avail, now); s != "" {
			l, why = s, "every path tripped: the earliest trip"
		}
		b.setLeader(l, now, "lead_init", why)
	} else {
		ls := b.st[b.leader]
		if cand, m := b.bestBy(avail, b.leader, true, now); cand != "" && m >= ls.Mean()+b.cfg.LeaderDelta && !b.muchSlower(cand, now) && !b.muchLaggier(cand, now) && !b.held(cand, now) {
			b.setLeader(cand, now, "lead_switch", fmt.Sprintf("posterior %.2f vs %.2f of %s", m, ls.Mean(), b.leader))
		} else if ls.ConsecutiveStalls() >= b.cfg.LeaderStallStrikes {
			if cand, _ := b.bestBy(avail, b.leader, false, now); cand != "" {
				old := b.leader
				b.setLeader(cand, now, "lead_stall", fmt.Sprintf("%d consecutive stalls on %s", ls.ConsecutiveStalls(), old))
				b.doubtAt = now
				ls.ResetStalls()
				b.demoted[old] = now
			}
		} else if cand, why := b.faster(avail, now); cand != "" {
			b.demoted[b.leader] = now
			b.setLeader(cand, now, "lead_slow", why)
		} else if cand, why := b.quicker(avail, now); cand != "" {
			b.demoted[b.leader] = now
			b.setLeader(cand, now, "lead_lag", why)
		}
	}

	primary, explore, reason := b.leader, false, "leader"
	for _, p := range avail {
		if p == b.leader {
			continue
		}
		floor := b.cfg.FloorMs
		if b.offNet(b.info(p)) {
			floor *= OffNetFloorFactor
		}
		if now-b.lastPick[p] >= floor {
			primary, explore, reason = p, true, "explore_floor"
			break
		}
	}
	if !explore {
		if p, share, why := b.speedProbe(avail, now); p != "" && b.exploreShare(now) < share {
			primary, explore, reason = p, true, why
		}
	}
	storm := b.Breaker.Storm(now)
	exploreCap := b.cfg.ExploreShare
	if storm && !b.leaderAnswers(now) {
		exploreCap = b.Breaker.cfg.StormExplore
	}
	if !explore && b.exploreShare(now) < exploreCap {
		// A path under a sweep's probe is being measured; one measured poor
		// while the leader delivers well would only make the user wait.
		_, slow := b.slowLeader(now)
		_, lag := b.laggyLeader(now)
		spare := !b.leaderUnheard(now) && !slow && !lag
		bestP, bestV := "", -1.0
		for _, p := range avail {
			if p != b.leader && (b.probing(p) || spare && b.knownPoor(p, now)) {
				continue
			}
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
	if tertiary == "" && !b.info(primary).White && !b.info(secondary).White {
		tertiary = b.whiteEscape(avail, now)
	}
	b.lastPick[primary] = now
	if primary == b.leader && b.askedAt <= b.st[primary].AnsweredAt {
		b.askedAt = now
	}
	b.picks = append(b.picks, pickRec{now, explore})
	d := b.Pinned(primary)
	d.Secondary, d.Tertiary, d.Explore, d.Reason = secondary, tertiary, explore, reason
	return d
}

// whiteEscape is an allow-listed path to dial third while the leader has not
// answered on this network: where allow-listing silences every other path, a
// first flow then gets through on it instead of waiting out silent dials. A
// leader that answers is ready long before the third dial is due.
func (b *Brain) whiteEscape(avail []string, now int64) string {
	if b.leaderAnswers(now) {
		return ""
	}
	best, bestM := "", -1.0
	for _, p := range avail {
		if i := b.info(p); i.White && !b.offNet(i) && b.st[p].Mean() > bestM {
			best, bestM = p, b.st[p].Mean()
		}
	}
	return best
}

// Pinned is the decision for a flow that must go over path and no other (a
// sweep's probe): its pacing of the first byte, no backup dial.
func (b *Brain) Pinned(primary string) Decision {
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
	return Decision{Primary: primary, Explore: true, Reason: "sweep", StaggerMs: stagger, FirstByteDeadlineMs: deadline}
}

// UDPOrder lists every awake path in the order a UDP association tries them:
// the leader, the other available paths by posterior mean (NotHTTP ones after
// the rest: they do not stand in for a failing leader), then the parked and
// tripped ones. UDP yields no receipts, so it follows what TCP flows proved,
// and asking is not a pick.
func (b *Brain) UDPOrder(now int64) []string {
	avail := b.available(now)
	out := make([]string, 0, len(b.paths))
	if contains(avail, b.leader) {
		out = append(out, b.leader)
	}
	rest := make([]string, 0, len(avail))
	for _, p := range avail {
		if p != b.leader {
			rest = append(rest, p)
		}
	}
	sort.SliceStable(rest, func(i, j int) bool {
		if ni, nj := b.info(rest[i]).NotHTTP, b.info(rest[j]).NotHTTP; ni != nj {
			return nj
		}
		return b.st[rest[i]].Mean() > b.st[rest[j]].Mean()
	})
	out = append(out, rest...)
	for _, p := range b.paths {
		if !b.asleep[p.ID] && !contains(out, p.ID) {
			out = append(out, p.ID)
		}
	}
	return out
}

// Drops counts the receipts Observe left out of the evidence, by why: the
// device slept during the flow, the system blocked the app's network, the
// network changed, no path connected, the destination was quarantined.
type Drops struct {
	Sleep     int `json:"sleep"`
	Blocked   int `json:"blocked"`
	NetChange int `json:"netchange"`
	NetDown   int `json:"netdown"`
	Dst       int `json:"dst"`
}

// Observe folds a receipt into the evidence, after differential diagnosis.
func (b *Brain) Observe(r Receipt) {
	if _, ok := b.st[r.Path]; !ok {
		return
	}
	now := r.AtMs
	if r.SleptMs >= SleepGraceMs {
		// A phone asleep loses its flows whatever the path: NAT mappings
		// expire and the radio goes quiet.
		b.Dropped++
		b.Drops.Sleep++
		b.J.Add(now, "drop_sleep", "the device slept during the flow: not evidence against the path", r.Path)
		return
	}
	if b.blockedAt != 0 && r.AtMs >= b.blockedAt-BlockSlackMs {
		b.Dropped++
		b.Drops.Blocked++
		b.J.Add(now, "drop_blocked", "the system blocked the app's network: not evidence against the path", r.Path)
		return
	}
	if r.AtMs-r.DurMs < b.switchedAt {
		// The flow began on the network the device has left.
		b.Dropped++
		b.Drops.NetChange++
		b.J.Add(now, "drop_netchange", "the network changed during the flow: not evidence for either network", r.Path)
		return
	}
	wireOK := r.WireReadyMs >= 0
	if wireOK {
		b.noteBack(r.Path, now) // may leave a restricted network: fetch the state after it
	}
	s := b.st[r.Path]
	b.Diag.NoteWire(r.Path, wireOK, now)
	if !wireOK && b.NetDown(now) && !b.networkUp(now) {
		b.Dropped++
		b.Drops.NetDown++
		b.J.Add(now, "drop_netdown", "no path connects: not evidence against the path", r.Path)
		return
	}
	if wireOK && !r.FirstByte() && r.Dst != "" {
		if b.Diag.DstQuarantined(r.Dst, now) {
			b.Dropped++
			b.Drops.Dst++
			return
		}
		b.Diag.NoteDst(r.Dst, r.Path, false, now)
	} else if r.FirstByte() {
		b.Diag.NoteDst(r.Dst, r.Path, true, now)
	}
	s.Observe(r, now, b.cfg.HalfLifeMs)
	b.measured(r.Path, now)
	if r.StallNoted && r.Sig() == SigThrottle {
		return // the breaker took this stall while the flow ran
	}
	if tripped, sig := b.Breaker.Note(r, now); tripped {
		b.tripped(r.Path, sig, now)
	}
}

// NoteStall takes a flow's first stall while the flow still runs. The app
// waits on the frozen bytes until its own timeout, half a minute on many, and
// every flow picked meanwhile would go to the same path: the stall counts
// against the path now, not when the app gives up.
func (b *Brain) NoteStall(path string, startMs, now int64) {
	s, ok := b.st[path]
	if !ok || startMs < b.switchedAt || b.blockedAt != 0 {
		return // the flow began on the network the device has left, or the system blocks the app's
	}
	s.stallRun++
	if tripped, sig := b.Breaker.NoteSig(path, SigThrottle, now); tripped {
		b.tripped(path, sig, now)
	}
}

// BlockSlackMs: the system resets the app's sockets as it blocks its network
// and tells the app a moment later, so what failed this long before Blocked
// is taken for the block as well.
const BlockSlackMs = 2000

// Blocked records that the system blocked the app's network (Android cuts a
// cached app off until a push wakes it, resetting its sockets): the flows it
// kills and those that fail while it lasts are not evidence against their
// paths, and the trips they caused are taken back. Unblocked ends it.
func (b *Brain) Blocked(now int64) {
	if b.blockedAt != 0 {
		return
	}
	b.blockedAt = now
	b.forgive(now - BlockSlackMs)
	b.J.Add(now, "net_blocked", "the system blocked the app's network", b.leader)
}

// Unblocked ends Blocked: flows begun before now are not evidence (as after a
// network change), and nothing tripped while the network was blocked.
func (b *Brain) Unblocked(now int64) {
	if b.blockedAt == 0 {
		return
	}
	b.forgive(b.blockedAt - BlockSlackMs)
	b.blockedAt = 0
	b.switchedAt = now
	b.J.Add(now, "net_unblocked", "the system gave the app its network back", b.leader)
}

func (b *Brain) forgive(since int64) {
	b.Breaker.Forgive(since)
	for path, at := range b.demoted {
		if at >= since {
			delete(b.demoted, path)
		}
	}
	if b.doubtAt >= since {
		b.doubtAt = 0
	}
}

func (b *Brain) tripped(path string, sig BlockSig, now int64) {
	if path == b.leader {
		b.demoted[path] = now
		b.leader = "" // force re-election on the next Pick, bypassing hysteresis
		b.doubtAt = now
		b.J.Add(now, "lead_trip", "breaker: "+sig.String()+" on leader", path)
	} else {
		b.J.Add(now, "trip", "breaker: "+sig.String(), path)
	}
}
