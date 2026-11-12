package brain

import "sort"

// spread.go — the leader's flows shared with its mates.
//
// One path taking nine flows in ten puts nearly all of a session's bytes on
// one address. Where a filter counts volume per address, the paths beside it
// stay idle while the leader's count runs up. With Config.Spread the flows
// the leader would take go, in turn, to the leader and to its mates: paths of
// the same Group (they come out at one address, so a site sees one visitor)
// that are proven here and now. Nothing is narrowed: exploration, the breaker
// and the leader's own rules work as before, and a mate that stops delivering
// stops being one by the same evidence that would keep it from leading.
//
// Exploration gives a path a flow in ten at most, and a leader that delivers
// well far fewer: left to it, a mate's five receipts take a quarter of an
// hour. So a path of the group with nothing against it is tried: one flow at
// a time until its receipts make it a mate, or the first failure ends that.

// spreadTrialWaitMs: a path on trial gets its next flow when the one before
// has left a receipt, or this long after it.
const spreadTrialWaitMs = 10_000

// fit reports whether path p may share the leader's flows at all: it is of
// the leader's group and kind, on this network, free of the breaker, not
// held back after a demotion, not under a sweep's probe, not known poor
// beside a leader that is not. Through a relay the whole group answers over
// LagMs, the leader too: there a mate is judged against the leader, by
// muchSlower and muchLaggier, or the fan would close where it is needed.
func (b *Brain) fit(p string, now int64) bool {
	li, i := b.info(b.leader), b.info(p)
	if p == b.leader || i.Group != li.Group || i.NotHTTP != li.NotHTTP || b.offNet(i) {
		return false
	}
	poor := b.knownPoor(p, now) && !b.knownPoor(b.leader, now)
	return !b.Breaker.Tripped(p, now) && !b.held(p, now) && !b.probing(p) && !poor
}

// mates lists up to Spread-1 paths fit to share the leader's flows, best
// first: those that by their own fresh receipts deliver within LeaderDelta of
// the leader, no slower and no later to answer.
func (b *Brain) mates(avail []string, now int64) []string {
	if b.cfg.Spread < 2 || b.leader == "" {
		return nil
	}
	ls := b.st[b.leader]
	if b.info(b.leader).Group == "" || ls == nil {
		return nil
	}
	var out []string
	for _, p := range avail {
		s := b.st[p]
		if !b.fit(p, now) || s.RecentReceipts(now, b.cfg.LeaderWindowMs) < b.cfg.LeaderMinReceipts || s.Mean() < ls.Mean()-b.cfg.LeaderDelta {
			continue
		}
		if b.muchSlower(p, now) || b.muchLaggier(p, now) {
			continue
		}
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool { return b.st[out[i]].Mean() > b.st[out[j]].Mean() })
	if len(out) > b.cfg.Spread-1 {
		out = out[:b.cfg.Spread-1]
	}
	return out
}

// recruit names a path to try as a mate, or "": one fit to share that its
// receipts have not made a mate yet (too few, or too few to outweigh its
// prior), with no failure among those it has, measured neither slower nor
// later to answer than the leader, and whose flow on trial, if any, has left
// its receipt. The likeliest by prior and memory goes first.
func (b *Brain) recruit(avail, mates []string, now int64) string {
	best, bestM := "", -1.0
	for _, p := range avail {
		s := b.st[p]
		if !b.fit(p, now) || contains(mates, p) || b.muchSlower(p, now) || b.muchLaggier(p, now) {
			continue
		}
		if s.evDelivB >= 0.5 || s.evFbB >= 0.5 || s.stallRun > 0 {
			continue
		}
		if at := b.trialAt[p]; at > s.LastEvidenceMs && now-at < spreadTrialWaitMs {
			continue
		}
		if m := s.Mean(); m > bestM {
			best, bestM = p, m
		}
	}
	return best
}

// spread names the path to take a flow the leader would have taken, and
// why: a mate in its turn ("spread"), a path on trial ("spread_trial"), or
// "" when it is the leader's turn or it shares with nobody. A leader that
// has not answered lately keeps its flows: they are what proves or dethrones
// it.
func (b *Brain) spread(avail []string, now int64) (string, string) {
	if b.cfg.Spread < 2 || b.info(b.leader).Group == "" || !b.leaderAnswers(now) {
		return "", ""
	}
	m := b.mates(avail, now)
	if len(m) < b.cfg.Spread-1 {
		if p := b.recruit(avail, m, now); p != "" {
			if b.trialAt == nil {
				b.trialAt = map[string]int64{}
			}
			b.trialAt[p] = now
			return p, "spread_trial"
		}
	}
	if len(m) == 0 {
		return "", ""
	}
	b.spreadN++
	if k := b.spreadN % (len(m) + 1); k > 0 {
		return m[k-1], "spread"
	}
	return "", ""
}
