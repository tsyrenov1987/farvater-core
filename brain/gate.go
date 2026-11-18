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

// Zone reports whether the network is a whitelist zone: the brain is in a
// restricted network, or no path meant for the open internet answered within
// GateWindowMs while at least two of them failed to connect or are tripped.
func (b *Brain) Zone(now int64) bool {
	if b.Restricted() {
		return true
	}
	since := now - GateWindowMs
	silent := 0
	for _, p := range b.paths {
		if p.White || vkGated(p) || cdnGated(p) {
			continue
		}
		if s := b.st[p.ID]; s != nil && s.AnsweredAt > 0 && s.AnsweredAt >= since {
			return false // the open internet gets through: not a whitelist zone
		}
		if t, ok := b.Diag.lastWireFail[p.ID]; ok && t >= since || b.Breaker.Tripped(p.ID, now) {
			silent++
		}
	}
	return silent >= 2
}

// VKOpen reports whether plain vkturn paths may take flows: a whitelist zone.
func (b *Brain) VKOpen(now int64) bool { return b.Zone(now) }

// CDNOpen reports whether CDNvideo paths and the bond may take flows: a
// whitelist zone on a cellular network.
func (b *Brain) CDNOpen(now int64) bool { return b.cellular() && b.Zone(now) }
