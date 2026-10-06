package brain

import (
	"fmt"
	"sort"
	"strings"
)

// memory.go — network contexts (DESIGN §9). Paths behave differently on home
// Wi-Fi, on a mobile network and on a mobile network that lets only
// allow-listed sites through, so the brain keeps its evidence per network: a
// network left keeps its state for the session and for Remember, a network met
// again starts from what was learned there. Memory only orders the fan: every
// path stays in it, and five fresh receipts outweigh anything remembered.

// Memory is what the brain keeps about its paths per network between sessions.
type Memory struct {
	V   int                              `json:"v"`
	Ctx map[string]map[string]PathMemory `json:"ctx"`
}

// PathMemory is one path's remembered evidence in one network.
type PathMemory struct {
	A          float64 `json:"a"`
	B          float64 `json:"b"`
	FA         float64 `json:"fa"`
	FB         float64 `json:"fb"`
	Cut16      bool    `json:"cut16,omitempty"`
	GoodputBps float64 `json:"goodput_bps,omitempty"`
	AtMs       int64   `json:"at_ms"`
}

const (
	MemoryTTLMs    = 7 * 24 * 3600 * 1000 // evidence older than this is forgotten
	MemoryWeight   = 0.5                  // remembered evidence counts at half weight
	MemoryContexts = 16                   // networks remembered at most, the most recent kept

	// RestrictedSuffix marks the restricted variant of a network: one that
	// still reaches allow-listed sites while the paths go silent.
	RestrictedSuffix = ":wl"
	// SilentWindowMs: paths whose wire failed this recently, and has not
	// connected since, count as shut out when a restricted network is entered.
	SilentWindowMs = 60_000
	// NetUpTrustMs: after an allow-listed site answered directly, this long a
	// path that fails to connect is evidence against it even when no path
	// connects: the network is up, so it is not the network.
	NetUpTrustMs = 120_000
)

// NewMemory returns an empty memory.
func NewMemory() *Memory { return &Memory{V: 1, Ctx: map[string]map[string]PathMemory{}} }

// Prune forgets evidence older than the TTL and all but the most recently
// measured networks.
func (m *Memory) Prune(now int64) {
	last := map[string]int64{}
	for ctx, ps := range m.Ctx {
		for id, p := range ps {
			if now-p.AtMs > MemoryTTLMs {
				delete(ps, id)
			} else if p.AtMs > last[ctx] {
				last[ctx] = p.AtMs
			}
		}
		if len(ps) == 0 {
			delete(m.Ctx, ctx)
		}
	}
	if len(m.Ctx) <= MemoryContexts {
		return
	}
	ctxs := make([]string, 0, len(m.Ctx))
	for ctx := range m.Ctx {
		ctxs = append(ctxs, ctx)
	}
	sort.Slice(ctxs, func(i, j int) bool { return last[ctxs[i]] > last[ctxs[j]] })
	for _, ctx := range ctxs[MemoryContexts:] {
		delete(m.Ctx, ctx)
	}
}

// Prior is a catalogue's weak Beta prior for one path.
type Prior struct{ A, B float64 }

// ctxState is a network the brain has left this session.
type ctxState struct {
	st          map[string]*PathState
	leader      string
	leaderSince int64
	breaker     *Breaker
	diag        *Diagnoser
}

// Ctx is the network context the brain files evidence under.
func (b *Brain) Ctx() string { return b.ctx }

// UseMemory gives the brain what a network may start from: its memory of
// earlier sessions (nil: none) and the catalogue's priors per network. The
// current network is seeded at once.
func (b *Brain) UseMemory(m *Memory, priors map[string]map[string]Prior, now int64) {
	b.mem, b.priors = m, priors
	b.seed(now)
}

// seed installs the priors of a network entered for the first time this
// session: the path's own memory of it first, else the catalogue's prior; in a
// restricted network a path the catalogue marks as entering through an
// allow-listed address starts ahead.
func (b *Brain) seed(now int64) {
	var mem map[string]PathMemory
	if b.mem != nil {
		mem = b.mem.Ctx[b.ctx]
	}
	cat := b.priors[b.ctx]
	if cat == nil {
		kind, _, _ := strings.Cut(b.ctx, ":")
		if b.Restricted() {
			kind += RestrictedSuffix
		}
		cat = b.priors[kind]
	}
	for _, p := range b.paths {
		s := b.st[p.ID]
		if pm, ok := mem[p.ID]; ok && now-pm.AtMs <= MemoryTTLMs {
			s.SetDelivPrior(pm.A, pm.B, MemoryWeight)
			s.SetFbPrior(pm.FA, pm.FB, MemoryWeight)
			s.Cut16, s.GoodputBps = pm.Cut16, pm.GoodputBps
		} else if pr, ok := cat[p.ID]; ok {
			s.SetDelivPrior(pr.A, pr.B, 1)
		} else if p.White && b.Restricted() {
			s.SetDelivPrior(3, 1, 1)
		}
	}
}

// SwitchContext moves the brain to another network. A flow begun before the
// change is not evidence for either network.
func (b *Brain) SwitchContext(ctx string, now int64) {
	if ctx == "" || ctx == b.ctx {
		return
	}
	b.enter(ctx, now, "ctx_switch", "the network changed")
	b.switchedAt = now
}

func (b *Brain) enter(ctx string, now int64, act, why string) {
	old := b.ctx
	b.saved[old] = ctxState{b.st, b.leader, b.leaderSince, b.Breaker, b.Diag}
	b.ctx = ctx
	b.silent, b.back = nil, nil
	if cs, ok := b.saved[ctx]; ok {
		delete(b.saved, ctx)
		b.st, b.leader, b.leaderSince, b.Breaker, b.Diag = cs.st, cs.leader, cs.leaderSince, cs.breaker, cs.diag
	} else {
		b.st = map[string]*PathState{}
		for _, p := range b.paths {
			b.st[p.ID] = &PathState{}
		}
		b.leader, b.leaderSince = "", 0
		b.Breaker, b.Diag = NewBreaker(b.cfg.Breaker), NewDiagnoser(b.paths)
		b.seed(now)
	}
	b.J.Add(now, act, why+": "+old+" → "+ctx, b.leader)
}

// Restricted reports whether the brain is in the restricted variant of its network.
func (b *Brain) Restricted() bool { return strings.HasSuffix(b.ctx, RestrictedSuffix) }

// NetworkUp records that an allow-listed site answered directly just now.
func (b *Brain) NetworkUp(now int64) { b.upAt, b.upSeen = now, true }

func (b *Brain) networkUp(now int64) bool { return b.upSeen && now-b.upAt <= NetUpTrustMs }

// EnterRestricted moves to the restricted variant of the current network. The
// caller saw an allow-listed site answer directly while no path connects: the
// network is up and shuts the paths out, so their failures count again (see
// NetworkUp). Its memory puts first the paths that delivered there before. The
// paths silent now are noted: when two of them connect again, the restriction
// is over and the brain returns to the plain network.
func (b *Brain) EnterRestricted(now int64) {
	b.NetworkUp(now)
	if b.Restricted() {
		return
	}
	silent := b.Diag.WireFailed(now - SilentWindowMs)
	b.enter(b.ctx+RestrictedSuffix, now, "restricted_on", fmt.Sprintf("allow-listed sites answer, %d paths silent", len(silent)))
	b.silent, b.back = map[string]bool{}, map[string]bool{}
	for _, p := range silent {
		b.silent[p] = true
	}
}

// noteBack counts the silent paths of a restricted network that connect again.
func (b *Brain) noteBack(path string, now int64) {
	if !b.silent[path] {
		return
	}
	b.back[path] = true
	if len(b.back) >= min(2, len(b.silent)) {
		b.enter(strings.TrimSuffix(b.ctx, RestrictedSuffix), now, "restricted_off", fmt.Sprintf("%d silent paths connect again", len(b.back)))
	}
}

// Remember writes the evidence of every network seen this session into the
// memory, prunes it and returns it (nil when the brain was given none). A path
// is written only once it has evidence of its own in that network.
func (b *Brain) Remember(now int64) *Memory {
	if b.mem == nil {
		return nil
	}
	put := func(ctx string, st map[string]*PathState) {
		for id, s := range st {
			if s.LastEvidenceMs == 0 {
				continue
			}
			m := b.mem.Ctx[ctx]
			if m == nil {
				m = map[string]PathMemory{}
				b.mem.Ctx[ctx] = m
			}
			m[id] = PathMemory{A: s.priorDelivA + s.evDelivA, B: s.priorDelivB + s.evDelivB, FA: s.priorFbA + s.evFbA, FB: s.priorFbB + s.evFbB,
				Cut16: s.Cut16, GoodputBps: s.GoodputBps, AtMs: s.LastEvidenceMs}
		}
	}
	put(b.ctx, b.st)
	for ctx, cs := range b.saved {
		put(ctx, cs.st)
	}
	b.mem.Prune(now)
	return b.mem
}
