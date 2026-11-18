package brain

// handshake.go — how soon after the last handshake to a name the next one
// came, and how it ended.
//
// A filter that punishes a client for many ClientHellos to one name in a
// short time would show as failures crowding on the short steps of the
// ladder below while handshakes made after a long quiet succeed. Like the
// volume ladder, these counts change no decision: they are read out through
// Status for the field journal.

// HsSteps is how many steps the handshake ladder has.
const HsSteps = 8

// hsEdges are the upper bounds, in milliseconds since the previous handshake
// to the same name, of steps 1 to 6. Step 0 is a handshake with none before
// it; the last step is ten minutes and more.
var hsEdges = [HsSteps - 2]int64{1000, 2000, 10_000, 60_000, 120_000, 600_000}

// HsHist counts handshakes by the step of the ladder their gap fell on.
type HsHist [HsSteps]int

// HsStep is the ladder step for a handshake gapMs after the previous one to
// its name; a negative gapMs is the first.
func HsStep(gapMs int64) int {
	if gapMs < 0 {
		return 0
	}
	for i, e := range hsEdges {
		if gapMs < e {
			return i + 1
		}
	}
	return HsSteps - 1
}

// HsEnd says how a handshake ended.
type HsEnd int

const (
	HsOK      HsEnd = iota
	HsFail          // refused, reset, or its answer did not verify
	HsTimeout       // no answer in time
)

// NoteHandshake counts a handshake made for path. One that failed while the
// system kept the app off the network, or while no path connected, is the
// network's doing and is not counted.
func (b *Brain) NoteHandshake(path string, gapMs int64, end HsEnd, now int64) {
	s, ok := b.st[path]
	if !ok {
		return
	}
	if end != HsOK && (b.blockedAt != 0 || (b.NetDown(now) && !b.networkUp(now))) {
		return
	}
	step := HsStep(gapMs)
	switch end {
	case HsOK:
		s.HsOK[step]++
	case HsFail:
		s.HsFail[step]++
	case HsTimeout:
		s.HsTimeout[step]++
	}
}
