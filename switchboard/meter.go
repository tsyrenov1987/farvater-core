package switchboard

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/tsyrenov1987/farvater-core/brain"
)

func nowMs() int64 { return time.Now().UnixMilli() }

// sleptMs is how long the device slept since start. The wall clock runs on
// through sleep and Go's monotonic clock does not (mach_absolute_time on Apple
// systems, CLOCK_MONOTONIC on Linux and Android): the difference is the time
// asleep.
func sleptMs(start time.Time) int64 {
	now := time.Now()
	d := now.Round(0).Sub(start.Round(0)) - now.Sub(start)
	if f := labSleep.Load(); f != nil {
		d += (*f)(start, now)
	}
	return d.Milliseconds()
}

// labSleep, when set (only by the chaos lab's build, sleep_chaos.go), adds a
// sleep the lab played by stopping the process: a stopped process's monotonic
// clock runs on, so the clocks alone do not show it. Atomic: every flow reads
// it while the lab sets it.
var labSleep atomic.Pointer[func(start, now time.Time) time.Duration]

// meter is the per-attempt byte ledger. It implements wire.Meter.
type meter struct {
	mu          sync.Mutex
	f           *flow
	c           *carried // the path's session totals; nil for a bare test meter
	up, down    int64
	firstUpAt   int64
	lastUpAt    int64
	lastDownAt  int64
	firstDownAt int64
	maxGap      int64
	busyMs      int64 // downstream time, idle pauses left out (see Down)
	busyDown    int64 // bytes inside it
	noted       bool  // the goodput went to the brain while the flow ran
	heldMs      int64 // time the path held back bytes the server had sent (see tick)
	heldDown    int64 // bytes that came inside it
	tickAt      int64 // the last tick after the first byte
	tickDown    int64 // down at it
	slowNoted   bool  // the flow went to the brain as held back (brain.NoteSlow)
	stalls      int
	inStall     bool
	stallNoted  bool // the first stall went to the brain while the flow ran
	tls         tlsTrack
	held        func() bool // the path's own stream stopped inside a record (wire.Framed), if it can tell
	asked       int64       // bytes the app sent since the last answer
	askedAt     int64       // when the first of them went
}

func (m *meter) Up(p []byte) {
	if m.c != nil {
		m.c.up.Add(int64(len(p)))
	}
	m.mu.Lock()
	m.up += int64(len(p))
	m.lastUpAt = nowMs()
	if m.asked == 0 {
		m.askedAt = m.lastUpAt
	}
	m.asked += int64(len(p))
	if m.firstUpAt == 0 {
		m.firstUpAt = m.lastUpAt
	}
	record := m.firstDownAt == 0
	m.mu.Unlock()
	if record {
		m.f.recordPrelude(p)
	}
}

func (m *meter) Down(p []byte) {
	if m.c != nil {
		m.c.down.Add(int64(len(p)))
	}
	now := nowMs()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.firstDownAt == 0 {
		m.firstDownAt = now
	}
	if m.lastUpAt > m.lastDownAt { // the app had sent something since the last answer
		if gap := now - m.lastUpAt; gap > m.maxGap {
			m.maxGap = gap
		}
	}
	// A pause inside a TLS record of the site is the path holding back bytes
	// the server already sent: busy time, however long (a shaped path hands
	// over one 16 KB record a second). A pause at a record boundary is busy
	// only when short; a longer one is the site with nothing to say.
	if gap := now - m.lastDownAt; m.lastDownAt > 0 && (gap <= brain.BusyGapMs || m.tls.midRecord()) {
		m.busyMs += min(gap, maxBusyGapMs)
		m.busyDown += int64(len(p))
	}
	m.tls.feed(p)
	m.down += int64(len(p))
	m.lastDownAt = now
	m.inStall = false
	m.asked, m.askedAt = 0, 0
}

// maxBusyGapMs caps what one pause adds to the busy clock: a phone that slept
// in the middle of a download does not make its path look slow.
const maxBusyGapMs = 5000

// tick is the stall watchdog. A server writes each TLS record whole, so a
// flow that goes quiet for stallMs in the middle of a record is missing bytes
// that were already on their way: a stall. Quiet at a record boundary is the
// server having nothing more to say, which is how every keep-alive connection
// spends most of its life, and is not evidence of anything. Flows that are not
// TLS get no stall verdict once they have answered. The site's records can
// stop whole while the path's own record is cut (held): a stall as well.
func (m *meter) tick(now, stallMs int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.firstDownAt == 0 || m.inStall {
		return
	}
	cut := m.tls.midRecord() || m.held != nil && m.held()
	if now-m.lastDownAt > stallMs && cut {
		m.inStall = true
		m.stalls++
		return
	}
	// A record cut at the tick, the site's or the path's own, is bytes the
	// server wrote whole and the path still holds: the time since the last
	// tick and what it brought go to the held clock. A flow between records
	// (the site thinking, a keep-alive connection idle) adds nothing.
	if m.tickAt > 0 && cut {
		m.heldMs += min(now-m.tickAt, maxBusyGapMs)
		m.heldDown += m.down - m.tickDown
	}
	m.tickAt, m.tickDown = now, m.down
}

// noteOnce reports, the first time only, whether the flow has carried enough
// to tell its path's goodput.
func (m *meter) noteOnce() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.noted || m.busyDown < brain.BigBytes {
		return false
	}
	m.noted = true
	return true
}

// slowOnce reports, the first time only, that the path has held the flow
// back: brain.HeldMs inside the site's records at under brain.HeldBps.
func (m *meter) slowOnce() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.slowNoted || m.heldMs < brain.HeldMs || m.heldDown*1000 >= m.heldMs*brain.HeldBps {
		return false
	}
	m.slowNoted = true
	return true
}

// stallOnce reports, the first time only, that the flow has stalled.
func (m *meter) stallOnce() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stallNoted || m.stalls == 0 {
		return false
	}
	m.stallNoted = true
	return true
}

// swallowedBytes: what an answered flow must have sent unanswered before the
// silence counts against its path while the flow is still open. A request of a
// messenger's long poll waits for its answer half a minute on a healthy path;
// it is small. An upload the path swallows is not: the app sends until its
// buffers fill.
const swallowedBytes = 16 << 10

// unansweredOnce reports, the first time only and only if no stall went to
// the brain yet, that the path swallowed an upload: the app sent
// swallowedBytes or more since the last answer, has sent nothing more for
// stallMs and got nothing back for UnansweredMs. A freeze that shows nowhere
// downstream. An upload still going out is the app waiting on its own bytes,
// not on the path.
func (m *meter) unansweredOnce(now, stallMs int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stallNoted || m.firstDownAt == 0 || m.asked < swallowedBytes ||
		now-m.askedAt < brain.UnansweredMs || now-m.lastUpAt < stallMs {
		return false
	}
	m.stallNoted = true
	return true
}

type snapshot struct {
	up, down, firstUpAt, firstDownAt, maxGap int64
	busyMs, busyDown                         int64
	noted, stallNoted                        bool
	stalls                                   int
	inStall                                  bool
	asked, askedAt, lastUpAt, lastDownAt     int64
	heldMs, heldDown                         int64
}

func (m *meter) snap() snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return snapshot{m.up, m.down, m.firstUpAt, m.firstDownAt, m.maxGap, m.busyMs, m.busyDown, m.noted, m.stallNoted, m.stalls, m.inStall, m.asked, m.askedAt, m.lastUpAt, m.lastDownAt, m.heldMs, m.heldDown}
}

// tlsTrack follows TLS record framing in a downstream byte stream. The
// record headers travel in the clear even though the app's TLS is end to end.
// The first header that does not parse (the stream is not TLS, or framing was
// lost) switches tracking off for the rest of the flow.
type tlsTrack struct {
	off  bool
	hdr  [5]byte
	hn   int // header bytes buffered
	need int // body bytes of the current record still to come
}

// maxRecord is the largest TLS ciphertext record: 2^14 + 2048 (TLS 1.2).
const maxRecord = 1<<14 + 2048

func (t *tlsTrack) feed(p []byte) {
	for len(p) > 0 && !t.off {
		if t.need > 0 {
			k := min(t.need, len(p))
			t.need -= k
			p = p[k:]
			continue
		}
		k := copy(t.hdr[t.hn:], p)
		t.hn += k
		p = p[k:]
		if t.hn < len(t.hdr) {
			return
		}
		t.hn = 0
		typ, major, n := t.hdr[0], t.hdr[1], int(t.hdr[3])<<8|int(t.hdr[4])
		if typ < 20 || typ > 23 || major != 3 || n == 0 || n > maxRecord {
			t.off = true
			return
		}
		t.need = n
	}
}

// midRecord reports whether the stream stopped inside a TLS record.
func (t *tlsTrack) midRecord() bool { return !t.off && (t.need > 0 || t.hn > 0) }
