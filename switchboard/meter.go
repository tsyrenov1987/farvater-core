package switchboard

import (
	"sync"
	"time"

	"github.com/tsyrenov1987/farvater-core/brain"
)

func nowMs() int64 { return time.Now().UnixMilli() }

// meter is the per-attempt byte ledger. It implements wire.Meter.
type meter struct {
	mu          sync.Mutex
	f           *flow
	up, down    int64
	lastUpAt    int64
	lastDownAt  int64
	firstDownAt int64
	maxGap      int64
	burstBytes  int64
	stalls      int
	inStall     bool
}

func (m *meter) Up(p []byte) {
	m.mu.Lock()
	m.up += int64(len(p))
	m.lastUpAt = nowMs()
	record := m.firstDownAt == 0
	m.mu.Unlock()
	if record {
		m.f.recordPrelude(p)
	}
}

func (m *meter) Down(n int) {
	now := nowMs()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.firstDownAt == 0 {
		m.firstDownAt = now
	}
	if m.lastUpAt > m.lastDownAt { // the app was waiting for an answer
		if gap := now - m.lastUpAt; gap > m.maxGap {
			m.maxGap = gap
		}
	}
	if now-m.lastDownAt > 3000 {
		m.burstBytes = 0
	}
	m.burstBytes += int64(n)
	m.down += int64(n)
	m.lastDownAt = now
	m.inStall = false
}

// tick is the stall watchdog: a flow that was waiting for an answer, or was in
// the middle of a transfer, and then went silent for stallMs is in a stall.
func (m *meter) tick(now, stallMs int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.firstDownAt == 0 || m.inStall {
		return
	}
	quiet := m.lastUpAt
	if m.lastDownAt > quiet {
		quiet = m.lastDownAt
	}
	pending := m.lastUpAt > m.lastDownAt
	if now-quiet > stallMs && (pending || m.burstBytes >= brain.EvidenceBytes) {
		m.inStall = true
		m.stalls++
	}
}

type snapshot struct {
	up, down, firstDownAt, maxGap int64
	stalls                        int
	inStall                       bool
}

func (m *meter) snap() snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return snapshot{m.up, m.down, m.firstDownAt, m.maxGap, m.stalls, m.inStall}
}
