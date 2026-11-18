package brain

import (
	"fmt"
	"strings"
)

// Two kinds of paths take flows only where they are meant to.
//
// On a cellular network every path is in the fan, whitelist zone or not
// (owner, 18.11.2026): nothing is gated there, and delivery sorts the paths.
// The rule of the same morning — CDNvideo and the bond only in a zone — took
// them and vkturn out of the fan each time the zone seemed over, the leader
// with them (iOS 69 on МТС: eight times in an hour).
//
// Off cellular, CDNvideo (catalogue "#door=cdnv") and the bond that carries a
// CDNvideo leg (rail "kilbond") take no flows: they ride a paid 10 Mbit/s
// door. Plain vkturn (rail "vkturn") rides VK's call relays on a pool of
// accounts that must not burn; off cellular it works in a whitelist zone,
// whether CDNvideo answers or not.
//
// A whitelist zone is assumed on a cellular network until the open internet
// proves itself there (Zone); on other networks it takes evidence. On
// cellular the zone no longer gates. The network is asked directly there
// (Verdict): in a zone the bond leads (bondLead), on the open internet the
// paid door and vkturn ride behind (backSeat).
//
// Outside its conditions a path stays in the catalogue and in memory and only
// takes no flows; the moment they hold, it is back in the fan. available()
// never narrows the fan to nothing, so a catalogue of only gated paths still
// runs.

// GateWindowMs is how fresh the evidence for the zone must be.
const GateWindowMs = 180_000

// DoorCDNvideo is the catalogue's "#door=" name of the CDNvideo entry.
const DoorCDNvideo = "cdnv"

func vkGated(p PathInfo) bool { return p.Rail == "vkturn" }

func cdnGated(p PathInfo) bool { return p.Door == DoorCDNvideo || p.Rail == "kilbond" }

// gated returns the paths kept out of the fan right now (nil: none).
func (b *Brain) gated(now int64) map[string]bool {
	if b.cellular() {
		return nil
	}
	zone := b.Zone(now)
	var out map[string]bool
	for _, p := range b.paths {
		if vkGated(p) && !zone || cdnGated(p) && !vkGated(p) {
			if out == nil {
				out = map[string]bool{}
			}
			out[p.ID] = true
		}
	}
	return out
}

// cellular reports whether the current network is a cellular one.
func (b *Brain) cellular() bool {
	kind, _, _ := strings.Cut(strings.TrimSuffix(b.ctx, RestrictedSuffix), ":")
	return kind == "cell"
}

// OpenAnswerMs is the answer time (Receipt.AnswerMs) under which a clean
// answer over a path meant for the open internet counts as the open internet
// getting through. In a whitelist zone the foreign paths that answer at all
// answer in 2–9 s at 1–3 KB/s (iOS 68 on МТС, 18.11.2026); one such answer
// used to cancel the zone and hide CDNvideo again.
const OpenAnswerMs = 2000

// OpenProofAnswers is how many quick clean answers over those paths prove the
// open internet; OpenProofKeepMs is how long the proof holds while no path
// fails after it.
const (
	OpenProofAnswers = 2
	OpenProofKeepMs  = 600_000
)

const openKeep = 4

func (s *PathState) noteOpen(now int64) {
	s.openAt = append(s.openAt, now)
	if len(s.openAt) > openKeep {
		s.openAt = s.openAt[1:]
	}
}

// openPath reports whether a path is meant for the open internet: the ones
// whose answers and failures tell a whitelist zone from the open internet.
func openPath(p PathInfo) bool { return !p.White && !vkGated(p) && !cdnGated(p) }

// ZoneRelapseMs is how long the open internet's proof is not taken again
// after the zone came back over one: on a line where the open paths answer in
// bursts and die again (МТС, 18.11.2026) each burst used to end the zone,
// take CDNvideo, the bond and vkturn out of the fan with their leader, and
// the next two failures brought them back — eight times an hour.
const ZoneRelapseMs = 30 * 60_000

// openProof returns when the open internet last proved itself on this network:
// the latest of quick clean answers over paths meant for it at no fewer than
// OpenProofAnswers entry addresses, within OpenProofKeepMs; 0 when there is no
// such proof. One address answering proves that address: a CDN front that
// answered twice and then failed eleven flows ended the zone (iOS 69 on МТС,
// 18.11.2026). A path whose flows are cut at 16 KB proves nothing, nor does an
// answer the zone's return has refuted, nor any for ZoneRelapseMs after it.
func (b *Brain) openProof(now int64) int64 {
	if b.relapseAt > 0 && now-b.relapseAt < ZoneRelapseMs {
		return 0
	}
	addrs, last := map[string]bool{}, int64(0)
	for _, p := range b.paths {
		s := b.st[p.ID]
		if !openPath(p) || s == nil || s.Cut16 {
			continue
		}
		for _, t := range s.openAt {
			if t >= now-OpenProofKeepMs && t <= now && t > b.relapseAt {
				addr := p.IP
				if addr == "" {
					addr = p.ID
				}
				addrs[addr] = true
				last = max(last, t)
			}
		}
	}
	if len(addrs) < OpenProofAnswers {
		return 0
	}
	return last
}

// zoneEvident reports whether the whitelist zone is known rather than assumed:
// the brain is in a restricted network, or the network itself said so when
// asked directly (Verdict); a direct verdict of the open internet is its proof.
// With no verdict the paths' own record decides (inferZone).
func (b *Brain) zoneEvident(now int64) (evident bool, proof int64) {
	if b.Restricted() {
		return true, 0
	}
	switch b.Verdict(now) {
	case VerdictZone:
		return true, 0
	case VerdictOpen:
		return false, b.verdictAt
	}
	return b.inferZone(now)
}

// inferZone is zoneEvident from the paths' record alone: at least two paths
// meant for the open internet failed to connect within GateWindowMs and after
// the open internet last proved itself (with no proof, a tripped one counts
// too), or the zone came back over a proof within ZoneRelapseMs. proof is
// openProof's. The paths fail for reasons of their own too (an address
// blocked, a node loaded, a poor radio), so this is a guess: it stands only
// until the network answers a direct probe.
func (b *Brain) inferZone(now int64) (evident bool, proof int64) {
	proof = b.openProof(now)
	since := now - GateWindowMs
	if proof > 0 {
		since = max(since, proof+1)
	}
	silent := 0
	for _, p := range b.paths {
		if !openPath(p) {
			continue
		}
		if t, ok := b.Diag.lastWireFail[p.ID]; ok && t >= since || proof == 0 && b.Breaker.Tripped(p.ID, now) {
			silent++
		}
	}
	if silent >= 2 {
		if proof > 0 {
			b.relapseAt = now // the proof did not hold
			b.J.Add(now, "zone_back", "open paths failed after the open internet's proof", "")
			proof = 0
		}
		return true, proof
	}
	return b.relapseAt > 0 && now-b.relapseAt < ZoneRelapseMs, proof
}

// Zone reports whether the network is a whitelist zone: the zone is evident
// (zoneEvident), or the network is cellular and the open internet has not
// proved itself on it (openProof). A phone starting on cellular does not know
// yet; until it does, CDNvideo, the bond and vkturn stay in the fan. Starting
// with them gated left a phone in a whitelist zone dialling only dead foreign
// paths, 15 s a try (iOS 68 / Android 60, 18.11.2026).
func (b *Brain) Zone(now int64) bool {
	evident, proof := b.zoneEvident(now)
	return evident || proof == 0 && b.cellular()
}

// bondLead returns the bond to lead with when the leader is to be chosen anew
// on a cellular network in an evident whitelist zone: there CDNvideo and VK
// carry the flows together (owner, 18.11.2026), and one leg failing does not
// cost the flow. A bond the breaker tripped or just dethroned is not it; ""
// outside those conditions.
func (b *Brain) bondLead(avail []string, now int64) string {
	if !b.cellular() {
		return ""
	}
	if evident, _ := b.zoneEvident(now); !evident {
		return ""
	}
	best, bestM := "", -1.0
	for _, p := range avail {
		if b.info(p).Rail != "kilbond" || b.Breaker.Tripped(p, now) || b.held(p, now) {
			continue
		}
		if m := b.st[p].Mean(); m > bestM {
			best, bestM = p, m
		}
	}
	return best
}

// bondHolds reports whether the leader is a bond that delivers: no flow of it
// left unanswered, its goodput not measured slow. Another path's longer record
// or quicker answer does not take the lead from it then; a trip, stalls, a
// run of failed flows, a sweep or a path measured several times faster do.
func (b *Brain) bondHolds(now int64) bool {
	if b.leader == "" || b.info(b.leader).Rail != "kilbond" {
		return false
	}
	_, slow := b.slowLeader(now)
	return !slow && !b.leaderUnheard(now)
}

// VKOpen reports whether plain vkturn paths may take flows: a cellular
// network, or a whitelist zone on any other.
func (b *Brain) VKOpen(now int64) bool { return b.cellular() || b.Zone(now) }

// CDNOpen reports whether CDNvideo paths and the bond may take flows: a
// cellular network.
func (b *Brain) CDNOpen(now int64) bool { return b.cellular() }

// Verdict is what the network itself said when asked directly, past the paths
// (switchboard.checkZone): allow-listed sites and neutral foreign sites are
// dialled side by side.
type Verdict int

const (
	VerdictUnknown Verdict = iota
	VerdictZone            // allow-listed sites answer, no foreign one does
	VerdictOpen            // both answer
)

func (v Verdict) String() string {
	return [...]string{"unknown", "zone", "open"}[v]
}

const (
	// VerdictConfirm is how many probes in a row must agree before the
	// verdict changes: one lost handshake is not a zone.
	VerdictConfirm = 2
	// VerdictOpenAnswers is how many foreign sites must answer for the open
	// internet; with fewer (and more than none) the probe says nothing: one
	// of them may be on an operator's list.
	VerdictOpenAnswers = 2
	// VerdictKeepMs is how long a verdict stands with no probe renewing it
	// (the phone slept, and may have moved).
	VerdictKeepMs = 15 * 60_000
	// How often the network is asked: until it has answered and while its
	// last answer is not confirmed; in a zone; on the open internet; and
	// while the paths' record disagrees with the verdict.
	ProbeUnsureMs = 10_000
	ProbeZoneMs   = 120_000
	ProbeOpenMs   = 300_000
	ProbeDoubtMs  = 60_000
)

// Verdict returns the network's direct verdict, VerdictUnknown off cellular
// and once it is older than VerdictKeepMs.
func (b *Brain) Verdict(now int64) Verdict {
	if b.verdict == VerdictUnknown || !b.cellular() || now-b.verdictAt > VerdictKeepMs {
		return VerdictUnknown
	}
	return b.verdict
}

// ZoneProbeDue reports whether the network is to be asked again, last asked
// at last. Only a cellular network not known as restricted is asked: whitelists are a mobile thing,
// and off cellular the zone gates on the paths' record as before.
func (b *Brain) ZoneProbeDue(now, last int64) bool {
	if !b.cellular() || b.Restricted() {
		return false // a restricted network is a zone already, and has its own check
	}
	every := int64(ProbeUnsureMs)
	if b.unclearRun >= VerdictConfirm {
		every = ProbeDoubtMs // the probe keeps saying nothing: asking faster will not help
	}
	if v := b.Verdict(now); v != VerdictUnknown && b.probeLast == v {
		every = ProbeOpenMs
		if v == VerdictZone {
			every = ProbeZoneMs
		}
		if ev, proof := b.inferZone(now); ev && v == VerdictOpen || proof > 0 && v == VerdictZone {
			every = ProbeDoubtMs
		}
	}
	return now-last >= every
}

// NoteZoneProbe takes one direct probe: whether an allow-listed site answered
// and how many of the neutral foreign sites did. No allow-listed answer means
// the network is down or the probe never left: it says nothing. A verdict
// changes on VerdictConfirm probes in a row; one that agrees with it renews it.
func (b *Brain) NoteZoneProbe(white bool, foreign int, now int64) {
	if !white || !b.cellular() {
		return
	}
	v := VerdictUnknown
	switch {
	case foreign >= VerdictOpenAnswers:
		v = VerdictOpen
	case foreign == 0:
		v = VerdictZone
	}
	if v == VerdictUnknown {
		b.probeLast, b.probeRun = VerdictUnknown, 0
		b.unclearRun++
		return
	}
	b.unclearRun = 0
	if v == b.probeLast {
		b.probeRun++
	} else {
		b.probeLast, b.probeRun = v, 1
	}
	was := b.Verdict(now)
	if v != was && b.probeRun < VerdictConfirm {
		return
	}
	b.verdict, b.verdictAt = v, now
	if v == was {
		return
	}
	b.J.Add(now, "zone_"+v.String(), fmt.Sprintf("asked directly: allow-listed sites answer, %d foreign; was %s", foreign, was), "")
	if v == VerdictOpen {
		b.stepBack(now)
	}
}

// backSeat reports whether p rides behind on this network: on a cellular
// network the open internet proved itself on directly, CDNvideo, the bond and
// vkturn stay in the fan (owner, 18.11.2026) but do not lead while a path
// meant for the open internet does the work — the door is paid and capped,
// the VK accounts must not burn. They get the stretched floor of an off-net
// path, are not chosen to lead anew over a free open path, and do not take
// the lead on a quicker answer alone (a Russian entry always answers
// sooner). Delivery still moves them: a leader that fails or is measured
// several times slower gives way to them like to any path.
func (b *Brain) backSeat(p PathInfo, now int64) bool {
	return (vkGated(p) || cdnGated(p)) && b.Verdict(now) == VerdictOpen
}

// front returns the paths of avail that may lead anew: all of them, or, where
// some ride behind (backSeat), the others the breaker has not tripped — when
// there are any.
func (b *Brain) front(avail []string, now int64) []string {
	var out []string
	for _, p := range avail {
		if !b.backSeat(b.info(p), now) && !b.Breaker.Tripped(p, now) {
			out = append(out, p)
		}
	}
	if len(out) == 0 || len(out) == len(avail) {
		return avail
	}
	return out
}

// stepBack hands the lead from a path that rides behind to one meant for the
// open internet, the moment the open internet proved itself: a phone starts
// on cellular assuming a zone, and the paid door led from then on.
func (b *Brain) stepBack(now int64) {
	if b.leader == "" || !b.backSeat(b.info(b.leader), now) {
		return
	}
	front := b.front(b.available(now), now)
	if contains(front, b.leader) {
		return // nothing else is free
	}
	l := b.answeredNow(front, now)
	if l == "" {
		l, _ = b.bestBy(front, "", false, now)
	}
	if l != "" {
		b.setLeader(l, now, "lead_open", "the open internet proved itself: the paid door steps back")
	}
}
