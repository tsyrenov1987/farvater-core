package brain

import (
	"fmt"
	"sort"
)

// A sweep measures paths side by side: each gets the same volume probe at
// the same time, and the leader goes at once to a path that delivers it
// FasterFactor times and SweepGapMs sooner than the leader does. Receipts of
// the app's own flows find such a path too, but one flow at a time, and each
// flow sent to a bad path to learn that is a page or a video the user waits
// for. A sweep spends probes instead, only while the leader is in doubt:
//
//   - acute: the leader's breaker tripped, it stalled out, it lost two
//     connect races in a row or left two requests unanswered
//     (NoteUnanswered; any path may be the one that still delivers, so the
//     sweep takes the available paths);
//   - chronic: the leader is measured slow, answers late or holds flows back
//     (NoteSlow); the sweep takes the paths with no goodput or answer time of
//     their own yet.
//
// The probes go through the Governor like any dial: no SNI or address sees a
// handshake burst (§1), whatever the number of paths.
type sweepRun struct {
	at      int64
	why     string
	start   map[string]int64 // path → when its probe began
	done    map[string]int64 // path → ms its probe took to deliver the whole body
	failed  map[string]bool
	left    int
	decided bool
}

// SweepGapMs is the least a sweep's winner must deliver its probe sooner
// than the leader to take the lead: a second or so is noise between two
// healthy paths, not a reason to move.
const SweepGapMs = 1000

// ProbeCapMs: a probe still running this long is abandoned. A path that
// carried EvidenceBytes by then is measured at that goodput.
const ProbeCapMs = 20_000

// HeldMs and HeldBps: a flow that has spent HeldMs inside the site's records,
// bytes the server had sent already coming in at under HeldBps, is held back
// by its path. A healthy path hands over a 16 KB record in a round trip or
// two even in slow start; pauses between records (the site thinking, a
// keep-alive connection idle) do not count.
const (
	HeldMs  = 2000
	HeldBps = 32 * KB
)

// NoteSlow takes a flow on path found held back while it runs (HeldMs,
// HeldBps). A flow under BigBytes measures no goodput, so a leader shaped
// while it carries only such flows (a feed of short videos) is otherwise never
// found slow. Two of them make the leader suspect: a sweep measures it.
func (b *Brain) NoteSlow(path string, heldDown, heldMs, startMs, now int64) {
	if path != b.leader || startMs < b.leaderSince || startMs < b.switchedAt {
		return
	}
	b.slowAt = append(b.slowAt, now)
	if len(b.slowAt) > 8 {
		b.slowAt = b.slowAt[len(b.slowAt)-8:]
	}
	if n := b.heldSince(b.sweptAt); n >= 1 && n <= 2 { // the two that make it suspect, not a flood
		b.J.Add(now, "held", fmt.Sprintf("%d KB in %d ms inside the site's records, flow %d of 2", heldDown>>10, heldMs, n), path)
	}
}

// heldSince counts the flows on the leader held back since it took the lead
// and after since.
func (b *Brain) heldSince(since int64) int {
	n := 0
	for _, at := range b.slowAt {
		if at >= b.leaderSince && at > since {
			n++
		}
	}
	return n
}

// AskBytes and AskMs: a flow that answered every request within AskMs, then
// sent AskBytes or more and has heard nothing back for AskMs while the app
// waits, is left unanswered by its path. Fewer bytes are an HTTP/2
// connection's control frames (PING, WINDOW_UPDATE: 31-45 bytes on the wire,
// two at the end of a download) or a close_notify, which expect no answer.
const (
	AskBytes = 128
	AskMs    = 2000
)

// NoteUnanswered takes a flow on path left unanswered (AskBytes, AskMs). A
// connection the app keeps open and the TSPU freezes under it shows nothing
// else: no record is cut, the request is small, and the app waits for its own
// timeout, 25 s and more, before it dials again. Two of them put the leader
// in doubt: a sweep probes it beside the other paths, and the flows waiting
// on a leader that does not deliver its probe are closed (ProbeLost). A
// messenger's long poll on a healthy leader costs a sweep, no more.
func (b *Brain) NoteUnanswered(path string, startMs, now int64) {
	if path != b.leader || startMs < b.leaderSince || startMs < b.switchedAt {
		return
	}
	b.unheardAt = append(b.unheardAt, now)
	if len(b.unheardAt) > 8 {
		b.unheardAt = b.unheardAt[len(b.unheardAt)-8:]
	}
	if n := b.unheardSince(b.sweptAt); n >= 1 && n <= 2 {
		b.J.Add(now, "unanswered", fmt.Sprintf("a request unanswered for %d ms, flow %d of 2", AskMs, n), path)
	}
}

// unheardSince counts the flows on the leader left unanswered since it took
// the lead and after since.
func (b *Brain) unheardSince(since int64) int {
	n := 0
	for _, at := range b.unheardAt {
		if at >= b.leaderSince && at > since {
			n++
		}
	}
	return n
}

// ProbeLost returns when path last lost a sweep without delivering its probe
// while another path delivered, if it has not led since; 0 if not.
func (b *Brain) ProbeLost(path string) int64 { return b.probeLost[path] }

// NoteRace takes a connect race a flow's first dial was in: lost when another
// path's dial came up first while it still hung. A leader whose dials hang
// while the runner-up's connect (an allow list, a block of new handshakes)
// has every flow rescued by the connect-stage retry, so none files a receipt
// against it, and it keeps the lead at the cost of the stagger on every flow.
// Two races lost in a row put it in doubt, which answers on connections
// already open do not end: a race it wins does.
func (b *Brain) NoteRace(path string, lost bool, startMs, now int64) {
	if path != b.leader || startMs < b.leaderSince || startMs < b.switchedAt {
		return
	}
	if !lost {
		b.raceLost, b.raceDoubt = 0, 0
		return
	}
	if b.raceLost++; b.raceLost == 2 {
		b.raceDoubt = now
		b.J.Add(now, "lead_race", "lost 2 connect races in a row: its dials hang while another path's come up", path)
	}
}

// suspect reports whether two flows on the leader were held back since it
// took the lead and since the last sweep, and its own fresh goodput (a big
// flow's, a probe's) does not say otherwise.
func (b *Brain) suspect(now int64) bool {
	if b.leader == "" {
		return false
	}
	if bps, _, fresh := b.st[b.leader].Goodput(now, b.cfg.GoodputFreshMs); fresh && bps >= b.cfg.SlowBps {
		return false
	}
	return b.heldSince(max(b.sweptAt, now-b.cfg.GoodputFreshMs-1)) >= 2
}

// SweepDue returns the paths to probe now, the leader first, and marks the
// sweep begun; nil when no sweep is due. The caller reports each probe with
// Swept and calls SweepCheck while they run.
func (b *Brain) SweepDue(now int64) []string {
	if b.cfg.SweepMs <= 0 || b.sw != nil && b.sw.left > 0 || b.sweptAt != 0 && now-b.sweptAt < b.cfg.SweepMs {
		return nil
	}
	avail := b.available(now)
	_, slow := b.slowLeader(now)
	_, lag := b.laggyLeader(now)
	held := !slow && b.suspect(now)
	// A doubt the leader has answered since (the next leader delivers) is over.
	acute := b.doubtAt > b.sweptAt && (b.leader == "" || !b.leaderAnswers(now)) || b.raceDoubt > b.sweptAt
	unheard := b.unheardSince(max(b.sweptAt, now-LeadFreshMs)) >= 2
	var cands []string
	why := ""
	switch {
	case acute || unheard || b.cfg.SweepAlways:
		switch {
		case acute:
			why = "the leader is in doubt"
		case unheard:
			why = "the leader leaves requests unanswered"
		default:
			why = "every sweep interval"
		}
		for _, p := range avail {
			if p != b.leader {
				cands = append(cands, p)
			}
		}
	case slow || lag || held:
		why = "the leader is slow"
		switch {
		case held:
			why = "the leader holds flows back"
		case !slow:
			why = "the leader answers late"
		}
		measured := 0
		for _, p := range avail {
			if p == b.leader {
				continue
			}
			_, _, fresh := b.st[p].Goodput(now, b.cfg.GoodputFreshMs)
			_, n := b.st[p].Answer(now, b.cfg.GoodputFreshMs)
			if (!(slow || held) || fresh) && (!lag || n >= lagSamples) {
				measured++
				continue
			}
			cands = append(cands, p)
		}
		// Twice SweepMax paths measured and none better: the network is slow,
		// not the leader's path. Further sweeps would cost without finding.
		if b.cfg.SweepMax > 0 && measured >= 2*b.cfg.SweepMax {
			return nil
		}
	default:
		return nil
	}
	if len(cands) == 0 {
		return nil
	}
	// Paths measured least lately first, then by a draw biased toward a path
	// unlike the leader, as speed probes go.
	lead := b.info(b.leader)
	draw := map[string]float64{}
	for _, p := range cands {
		draw[p] = 0.85*b.st[p].Sample(b.rng) + 0.15*float64(diversity(b.info(p), lead))/3
	}
	sort.SliceStable(cands, func(i, j int) bool {
		si, sj := b.st[cands[i]].LastEvidenceMs, b.st[cands[j]].LastEvidenceMs
		if (si == 0) != (sj == 0) {
			return si == 0
		}
		return draw[cands[i]] > draw[cands[j]]
	})
	if n := b.cfg.SweepMax; n > 0 && len(cands) > n {
		cands = cands[:n]
	}
	out := cands
	if b.leader != "" && contains(avail, b.leader) {
		out = append([]string{b.leader}, cands...)
	}
	b.sweptAt = now
	b.sw = &sweepRun{at: now, why: why, start: map[string]int64{}, done: map[string]int64{}, failed: map[string]bool{}, left: len(out)}
	for _, p := range out {
		b.sw.start[p] = now
	}
	b.J.Add(now, "sweep", fmt.Sprintf("%s: probing %d paths", why, len(out)), b.leader)
	return out
}

// Swept takes a probe's end: bytes carried in ms, whole if the body came in
// full. A whole body, or EvidenceBytes in a probe run to ProbeCapMs, measures
// the path's goodput.
func (b *Brain) Swept(path string, bytes, ms int64, whole bool, now int64) {
	if b.sw == nil {
		return
	}
	if _, ok := b.sw.start[path]; !ok {
		return
	}
	// A probe begun on a network the device has left says nothing about this one.
	if s := b.st[path]; b.sw.at >= b.switchedAt && ms > 0 && (whole || bytes >= EvidenceBytes && ms >= ProbeCapMs) {
		s.noteGoodput(bytes, ms, now)
	}
	if b.sw.at < b.switchedAt {
		b.sw.failed[path] = true // back, though it measured nothing here
		b.sw.left--
		return
	}
	if whole {
		b.sw.done[path] = ms
	} else {
		b.sw.failed[path] = true
	}
	b.sw.left--
	b.sweepVerdict(now)
}

// probing reports whether p's probe of the sweep under way is still out.
func (b *Brain) probing(p string) bool {
	w := b.sw
	if w == nil || w.left <= 0 {
		return false
	}
	if _, ok := w.start[p]; !ok {
		return false
	}
	_, done := w.done[p]
	return !done && !w.failed[p]
}

// SweepCheck lets the sweep decide on time: a leader whose probe has not
// come in FasterFactor times the winner's time is that much slower already.
// It reports whether the sweep is still out.
func (b *Brain) SweepCheck(now int64) bool {
	if b.sw == nil {
		return false
	}
	b.sweepVerdict(now)
	return b.sw.left > 0
}

func (b *Brain) sweepVerdict(now int64) {
	w := b.sw
	if w == nil || w.decided {
		return
	}
	if w.at < b.switchedAt {
		w.decided = true // begun on a network the device has left
		return
	}
	best, bestMs := "", int64(0)
	for p, ms := range w.done {
		if b.held(p, now) || b.Breaker.Tripped(p, now) || b.asleep[p] {
			continue
		}
		if best == "" || ms < bestMs || ms == bestMs && p < best {
			best, bestMs = p, ms
		}
	}
	if best == "" {
		return
	}
	lead := b.leader
	if best == lead {
		w.decided = true
		return
	}
	gap := max(int64(b.cfg.FasterFactor*float64(bestMs)), bestMs+SweepGapMs)
	lms, ldone := w.done[lead]
	since, probed := w.start[lead]
	if !probed {
		since = w.at
	}
	why := ""
	switch {
	case lead == "":
		why = fmt.Sprintf("probe in %d ms, no leader", bestMs)
	case ldone && lms >= gap:
		why = fmt.Sprintf("probe in %d ms vs %d ms on %s", bestMs, lms, lead)
	case ldone:
		w.decided = true // the leader held its own
		return
	case w.failed[lead]:
		why = fmt.Sprintf("probe in %d ms, failed on %s", bestMs, lead)
	case now-since >= gap:
		why = fmt.Sprintf("probe in %d ms, not in %d ms on %s", bestMs, now-since, lead)
	default:
		return
	}
	w.decided = true
	if lead != "" {
		b.demoted[lead] = now
		if probed && !ldone {
			b.probeLost[lead] = now
		}
	}
	b.setLeader(best, now, "lead_sweep", why)
}
