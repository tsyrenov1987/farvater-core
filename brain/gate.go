package brain

import "strings"

// Two kinds of paths take flows only where they are meant to.
//
// CDNvideo (catalogue "#door=cdnv") and the bond that carries a CDNvideo leg
// (rail "kilbond") ride a paid 10 Mbit/s door. The owner's rule (18.11.2026):
// they work only on a cellular network, and only in a whitelist zone. The
// audit of 18.11 found ~90 % of their bytes going to phones whose foreign
// paths answered in the same hour, so the door was full of traffic that had
// other ways out.
//
// Plain vkturn (rail "vkturn") rides VK's call relays on a pool of accounts
// that must not burn. Rule of 16.11, widened 18.11: it works in a whitelist
// zone on any network, whether CDNvideo answers or not — it is there to help
// when CDNvideo is full or down.
//
// A whitelist zone is assumed on a cellular network until the open internet
// proves itself there (Zone); on other networks it takes evidence.
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
	zone := b.Zone(now)
	cdnOpen := zone && b.cellular()
	var out map[string]bool
	for _, p := range b.paths {
		if vkGated(p) && !zone || cdnGated(p) && !vkGated(p) && !cdnOpen {
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
// the brain is in a restricted network, at least two paths meant for the open
// internet failed to connect within GateWindowMs and after the open internet
// last proved itself (with no proof, a tripped one counts too), or the zone
// came back over a proof within ZoneRelapseMs. proof is openProof's.
func (b *Brain) zoneEvident(now int64) (evident bool, proof int64) {
	if b.Restricted() {
		return true, 0
	}
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

// VKOpen reports whether plain vkturn paths may take flows: a whitelist zone.
func (b *Brain) VKOpen(now int64) bool { return b.Zone(now) }

// CDNOpen reports whether CDNvideo paths and the bond may take flows: a
// whitelist zone on a cellular network.
func (b *Brain) CDNOpen(now int64) bool { return b.cellular() && b.Zone(now) }
