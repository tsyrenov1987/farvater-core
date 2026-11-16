package brain

// Plain vkturn paths (rail "vkturn", not the kilbond bond) ride VK's call
// relays on a pool of accounts that must not burn. The owner's rule
// (16.11.2026): they work only in a whitelist zone, and only while a CDNvideo
// path works. Outside that the path stays in the catalogue and in memory, it
// only takes no flows; the moment the zone and CDNvideo are both seen, it is
// back in the fan. The bond is not gated: it carries a CDNvideo leg itself
// and is chosen by delivery like any other path.

// GateWindowMs is how fresh the evidence for the zone and for CDNvideo must be.
const GateWindowMs = 180_000

// DoorCDNvideo is the catalogue's "#door=" name of the CDNvideo entry.
const DoorCDNvideo = "cdnv"

func vkGated(p PathInfo) bool { return p.Rail == "vkturn" }

// gated returns the paths kept out of the fan right now (nil: none).
func (b *Brain) gated(now int64) map[string]bool {
	var vk []string
	for _, p := range b.paths {
		if vkGated(p) {
			vk = append(vk, p.ID)
		}
	}
	if len(vk) == 0 || b.VKOpen(now) {
		return nil
	}
	out := make(map[string]bool, len(vk))
	for _, id := range vk {
		out[id] = true
	}
	return out
}

// VKOpen reports whether plain vkturn paths may take flows: a CDNvideo path
// got an answer within GateWindowMs, and the network is a whitelist zone —
// the brain is in a restricted network, or no path meant for the open
// internet answered within the window while at least two of them failed to
// connect or are tripped.
func (b *Brain) VKOpen(now int64) bool {
	since := now - GateWindowMs
	cdn := false
	for _, p := range b.paths {
		if p.Door == DoorCDNvideo && p.Rail != "vkturn" && p.Rail != "kilbond" {
			if s := b.st[p.ID]; s != nil && s.AnsweredAt > 0 && s.AnsweredAt >= since {
				cdn = true
				break
			}
		}
	}
	if !cdn {
		return false
	}
	if b.Restricted() {
		return true
	}
	silent := 0
	for _, p := range b.paths {
		if p.White || vkGated(p) || p.Rail == "kilbond" {
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
