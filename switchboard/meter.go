package switchboard

import (
	"sync"
	"time"
)

func nowMs() int64 { return time.Now().UnixMilli() }

// sleptMs is how long the device slept since start. The wall clock runs on
// through sleep and Go's monotonic clock does not (mach_absolute_time on Apple
// systems, CLOCK_MONOTONIC on Linux and Android): the difference is the time
// asleep.
func sleptMs(start time.Time) int64 {
	now := time.Now()
	return (now.Round(0).Sub(start.Round(0)) - now.Sub(start)).Milliseconds()
}

// meter is the per-attempt byte ledger. It implements wire.Meter.
type meter struct {
	mu          sync.Mutex
	f           *flow
	up, down    int64
	firstUpAt   int64
	lastUpAt    int64
	lastDownAt  int64
	firstDownAt int64
	maxGap      int64
	stalls      int
	inStall     bool
	tls         tlsTrack
}

func (m *meter) Up(p []byte) {
	m.mu.Lock()
	m.up += int64(len(p))
	m.lastUpAt = nowMs()
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
	m.tls.feed(p)
	m.down += int64(len(p))
	m.lastDownAt = now
	m.inStall = false
}

// tick is the stall watchdog. A server writes each TLS record whole, so a
// flow that goes quiet for stallMs in the middle of a record is missing bytes
// that were already on their way: a stall. Quiet at a record boundary is the
// server having nothing more to say, which is how every keep-alive connection
// spends most of its life, and is not evidence of anything. Flows that are not
// TLS get no stall verdict once they have answered.
func (m *meter) tick(now, stallMs int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.firstDownAt == 0 || m.inStall {
		return
	}
	if now-m.lastDownAt > stallMs && m.tls.midRecord() {
		m.inStall = true
		m.stalls++
	}
}

type snapshot struct {
	up, down, firstUpAt, firstDownAt, maxGap int64
	stalls                                   int
	inStall                                  bool
}

func (m *meter) snap() snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return snapshot{m.up, m.down, m.firstUpAt, m.firstDownAt, m.maxGap, m.stalls, m.inStall}
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
