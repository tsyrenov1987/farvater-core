package brain

// A phone's radio gone for ten seconds (a tunnel, a dead zone, a cell handed
// over) answers no SYN on any path. NetDown does not see it at first: flows
// connected inside its window, before the radio went. Counted at once, the
// dials that time out in that silence trip the leader and the paths raced
// with it at every such gap; the lead goes to whatever path is left, and
// stays there for the breaker's hold after the radio is back.
//
// A dial that timed out while no path connected or answered is held instead
// (hold), and what happens next decides:
//
//   - its path connects: the network was silent, not the path. The held
//     receipts are forgotten.
//   - another path was connected and delivering while the held dial was
//     out, or, dialled right after it, connects at once (settle): the
//     network was up while the path was shut.
//     The held receipts count then: a path blocked alone, with the next path
//     taking its flow, is counted as before.
//   - its path times out again while another path connected or answered: the
//     same, the held receipts count with the new one.
//   - none of these within SilentHoldMs: the held receipts say nothing by now.
//
// Only a path that connected within SilentHoldMs before the dial is held: one
// that never did, or not lately, has no record the silence could wrong, and
// on a network where the first paths tried are all shut the brain must learn
// it from their first timeouts.
//
// A path connecting slowly after the silence says nothing of the held dial:
// its SYN waited for the radio too. A network the white probe proved up
// (networkUp) holds nothing: its failures count at once.

// SilentHoldMs is how long a held receipt may wait; SilentHoldMax is how many
// a path holds. A dial that began within SilentNextMs of a held dial's end and
// connected inside SilentFastMs proves the network was up then.
const (
	SilentHoldMs  = 60_000
	SilentHoldMax = 4
	SilentNextMs  = 500
	SilentFastMs  = 1000
)

type heldDials struct {
	rs []Receipt // AtMs is set: when each dial ended
}

// alive records the moment a path connected or answered.
func (d *Diagnoser) alive(at int64) { d.aliveAt = max(d.aliveAt, at) }

// hold takes a dial of r.Path that timed out. It reports whether the receipt
// is held for now; before it reports false it may hand back receipts held
// earlier, for the caller to count first.
func (b *Brain) hold(r Receipt, now int64) (bool, []Receipt) {
	d := b.Diag
	h := d.held[r.Path]
	if h != nil {
		kept := h.rs[:0]
		for _, e := range h.rs {
			if now-e.AtMs <= SilentHoldMs {
				kept = append(kept, e)
			}
		}
		h.rs = kept
	}
	if ok, was := d.lastWireOK[r.Path]; d.aliveAt >= now-r.DurMs || !was || now-r.DurMs-ok > SilentHoldMs {
		// The network was up during this dial, or the path has not connected
		// lately and has no record to protect: the timeout counts.
		delete(d.held, r.Path)
		if h == nil {
			return false, nil
		}
		return false, h.rs
	}
	if h == nil {
		h = &heldDials{}
		d.held[r.Path] = h
	}
	if len(h.rs) < SilentHoldMax {
		r.AtMs = now
		h.rs = append(h.rs, r)
	}
	b.J.Add(now, "hold_silent", "its dial timed out and no path connected meanwhile: held", r.Path)
	return true, nil
}

// settle takes a receipt whose wire connected, and hands back the held
// receipts it proves against: those of other paths whose dial was still out,
// or had just ended, when this one began and connected at once.
func (b *Brain) settle(r Receipt, now int64) []Receipt {
	d := b.Diag
	began := now - r.DurMs
	up, last := began+r.WireReadyMs, began+r.WireReadyMs
	if r.FirstByteMs >= 0 {
		last = began + r.FirstByteMs
	}
	if r.Delivered() && r.MaxGapMs < SilentFastMs {
		last = now // bytes kept coming to the end
	}
	d.alive(last)
	if len(d.held) == 0 {
		return nil
	}
	fast := r.WireReadyMs < SilentFastMs
	var out []Receipt
	for _, p := range b.paths { // in catalogue order: the same every run
		h := d.held[p.ID]
		if h == nil || p.ID == r.Path {
			continue
		}
		kept := h.rs[:0]
		for _, e := range h.rs {
			from := e.AtMs - e.DurMs
			if up <= e.AtMs && last >= from || fast && began <= e.AtMs+SilentNextMs && up >= from {
				out = append(out, e)
			} else {
				kept = append(kept, e)
			}
		}
		if h.rs = kept; len(kept) == 0 {
			delete(d.held, p.ID)
		}
	}
	return out
}
