package brain

// Diagnoser tells a dead path from a dead local network and from a dead destination.
type Diagnoser struct {
	paths        []PathInfo
	lastWireFail map[string]int64
	lastWireOK   map[string]int64
	dstFails     map[string]map[string]bool
	dstQ         map[string]int64
	parkedUntil  map[string]int64

	NetWindowMs   int64 // window for "everything fails" (10 s)
	DstQuarantine int64 // how long a destination is quarantined (5 min)
	FreezeParkMs  int64 // how long paths of a frozen SNI are parked (30 s)
	FreezePairMs  int64 // two wire failures of one SNI inside this window = freeze suspicion (5 s)
}

// NewDiagnoser returns a diagnoser for the given paths.
func NewDiagnoser(paths []PathInfo) *Diagnoser {
	return &Diagnoser{paths: paths, lastWireFail: map[string]int64{}, lastWireOK: map[string]int64{}, dstFails: map[string]map[string]bool{},
		dstQ: map[string]int64{}, parkedUntil: map[string]int64{}, NetWindowMs: 10_000, DstQuarantine: 5 * 60_000, FreezeParkMs: 30_000, FreezePairMs: 5_000}
}

// NoteWire records whether a path's wire connected.
func (d *Diagnoser) NoteWire(path string, ok bool, now int64) {
	if ok {
		d.lastWireOK[path] = now
		delete(d.parkedUntil, path)
		return
	}
	d.lastWireFail[path] = now
	sni := d.sniOf(path)
	if sni == "" {
		return
	}
	for _, q := range d.paths {
		if q.ID == path || q.SNI != sni {
			continue
		}
		if t, ok := d.lastWireFail[q.ID]; ok && now-t <= d.FreezePairMs {
			d.parkedUntil[path] = now + d.FreezeParkMs
			d.parkedUntil[q.ID] = now + d.FreezeParkMs
		}
	}
}

func (d *Diagnoser) sniOf(path string) string {
	for _, p := range d.paths {
		if p.ID == path {
			return p.SNI
		}
	}
	return ""
}

// NetDown suspects the local network when ≥2 distinct paths failed at the wire
// inside the window and nothing connected in that window.
func (d *Diagnoser) NetDown(now int64) bool {
	for _, t := range d.lastWireOK {
		if now-t <= d.NetWindowMs {
			return false
		}
	}
	fails := 0
	for _, t := range d.lastWireFail {
		if now-t <= d.NetWindowMs {
			fails++
		}
	}
	return fails >= 2
}

// Parked reports whether a path is parked after a freeze suspicion.
func (d *Diagnoser) Parked(path string, now int64) bool {
	t, ok := d.parkedUntil[path]
	return ok && now < t
}

// NoteDst records a destination outcome; two distinct paths failing on one
// destination quarantine it (the destination is dead, not the paths).
func (d *Diagnoser) NoteDst(dst, path string, ok bool, now int64) {
	if dst == "" {
		return
	}
	if ok {
		delete(d.dstFails, dst)
		return
	}
	m := d.dstFails[dst]
	if m == nil {
		m = map[string]bool{}
		d.dstFails[dst] = m
	}
	m[path] = true
	if len(m) >= 2 {
		d.dstQ[dst] = now + d.DstQuarantine
		delete(d.dstFails, dst)
	}
}

// DstQuarantined reports whether failures on this destination are currently not evidence.
func (d *Diagnoser) DstQuarantined(dst string, now int64) bool {
	t, ok := d.dstQ[dst]
	return ok && now < t
}

// WireFailed lists the paths whose wire failed at or after since and has not
// connected since.
func (d *Diagnoser) WireFailed(since int64) []string {
	var out []string
	for _, p := range d.paths {
		if t, ok := d.lastWireFail[p.ID]; ok && t >= since && d.lastWireOK[p.ID] < t {
			out = append(out, p.ID)
		}
	}
	return out
}
