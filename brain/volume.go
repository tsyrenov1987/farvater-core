package brain

// volume.go — how many bytes had gone through when something broke.
//
// The breaker says that a path was cut and by what signature; it does not say
// at what volume. A filter that freezes a connection after some amount of
// data would show as cuts crowding into one step of the ladder below while
// the flows that ended by themselves spread over all of it. These counts
// change no decision: they are read out through Status for the field journal.

// VolSteps is how many steps the volume ladder has.
const VolSteps = 8

// volEdges are the upper bounds of the ladder's steps but the last, which has
// none: under 4 KB (little more than the answer's headers), 4–12 KB, 12–28 KB
// (the cut16 window), 28–256 KB, 256 KB–4 MB, 4–32 MB, 32–128 MB and beyond.
var volEdges = [VolSteps - 1]int64{4 * KB, Cut16Lo, Cut16Hi, BigBytes, 4 << 20, 32 << 20, 128 << 20}

// VolHist counts events by the step of the ladder their byte count fell on.
type VolHist [VolSteps]int

// VolStep is the ladder step n bytes fall on.
func VolStep(n int64) int {
	for i, e := range volEdges {
		if n < e {
			return i
		}
	}
	return VolSteps - 1
}

// ConnEnd says how a connection shared by a path's flows ended.
type ConnEnd int

const (
	ConnOurs  ConnEnd = iota // we let it go: rotated, left idle, closed with the tunnel
	ConnFin                  // the far side closed it
	ConnReset                // it broke under us: a reset, a transport error
	ConnDead                 // it went silent: a PING was never answered
)

// noteFlowEnd counts a flow that had its first byte by how it ended and how
// much had come down by then.
func (s *PathState) noteFlowEnd(r Receipt) {
	if !r.FirstByte() {
		return
	}
	step := VolStep(r.Down)
	switch r.End {
	case EndWireReset:
		s.CutReset[step]++
	case EndTimeout, EndStallAbandon:
		s.CutStall[step]++
	default:
		s.Ended[step]++
	}
}

// NoteConnEnd counts the end of a connection that path's flows shared: how it
// ended and how many bytes it had carried, both ways. startMs is when the
// connection was made and sleptMs how long the device slept since. A
// connection is not evidence where a flow would not be: one the device slept
// through, one made on the network it has left, one that ended while the
// system kept the app off the network or while no path connected.
func (b *Brain) NoteConnEnd(path string, end ConnEnd, bytes, startMs, sleptMs, now int64) {
	s, ok := b.st[path]
	if !ok || sleptMs >= SleepGraceMs || startMs < b.switchedAt || b.blockedAt != 0 {
		return
	}
	if end != ConnOurs && b.NetDown(now) && !b.networkUp(now) {
		return
	}
	step := VolStep(bytes)
	switch end {
	case ConnOurs:
		s.ConnOurs[step]++
	case ConnFin:
		s.ConnFin[step]++
	case ConnReset:
		s.ConnReset[step]++
	case ConnDead:
		s.ConnDead[step]++
	}
}
