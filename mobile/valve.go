package mobile

import (
	"runtime/debug"
	"runtime/metrics"
	"sync"
	"sync/atomic"
	"time"
)

// The valve: the soft limit (SetMemoryLimit) lets a burst of allocations run past
// it while the collector, held to half the CPU, catches up, and an iOS tunnel past
// about 50 MiB is killed on the spot. Near that edge the core collects at once and
// hands the free pages back to the system: a pause of a few milliseconds, only then.
// Away from the edge it does nothing, so the speed and the choice of paths are the
// same as without it.
var (
	valveAt    atomic.Int64 // bytes the runtime may hold from the OS before the valve opens; 0: off
	valveFired atomic.Int64
	valveOnce  sync.Once

	// pressed: the valve opened and the runtime still held the line after it,
	// so the memory is live, not garbage: new flows are turned away (pressed())
	// until it is back under shedClear of the line.
	pressedOn atomic.Bool
	shedCount atomic.Int64
	lastLetIn atomic.Int64 // unix ms of the last flow let in while pressed
)

// While pressed one new flow in shedTrickle still gets in: a phone whose
// live memory sits at the line for minutes keeps working, slowly, instead of
// refusing everything; a burst of hundreds is what gets turned away.
const (
	shedClearNum = 85 // percent of the line
	shedTrickle  = 250 * time.Millisecond
)

// pressed is the switchboard's Config.Pressed on the phones.
func pressed() bool {
	if !pressedOn.Load() && !burstPressed() {
		return false
	}
	now := time.Now().UnixMilli()
	last := lastLetIn.Load()
	if now-last >= shedTrickle.Milliseconds() && lastLetIn.CompareAndSwap(last, now) {
		return false
	}
	shedCount.Add(1)
	return true
}

// The valve looks often only when the runtime is near the line, so an idle phone
// is not woken four times a second.
// The valve looks at the memory every 250 ms at best, and a flow grows after
// it is let in: its wire dials, its buffers fill. A phone coming back to a
// network, or every app reconnecting after a path switched, opens a hundred
// flows within a second, all let in before the valve's next look; on the Mac
// harness (16.11) 115 flows opened at once took the Go runtime from 25 to 47 MB
// in under ten seconds, and the iOS tunnel is killed at about 50 MiB in all.
// So while flows arrive fast, each new one is weighed at the door: the memory
// now plus what the flows let in within the last burstWindow will still take
// (burstFlowCost each, measured: 21.5 MB over 115 flows) must stay under the
// line, or the flow is turned away like a pressed one (one per shedTrickle
// still gets in). A phone opening flows at an ordinary pace never reads the
// memory here.
// The door's line is the valve's line and a quarter: many of the recent flows
// already show in the memory or are gone, so weighing them against the valve's
// own line turned away a burst the phone could carry (Mac harness, 150 flows at
// once: 90 served, peak 26.6 MB; against line+25 %: 175 served, peak 38 MB; no
// door at all: 188 served, peak 46.5 MB, at the edge of jetsam).
const (
	burstWindow   = 2 * time.Second
	burstFlows    = 16        // flows let in within burstWindow before the door weighs
	burstFlowCost = 192 << 10 // what a new flow takes once it carries data
	burstLineNum  = 125       // percent of the valve's line the door weighs against
)

// burstOver says whether recent flows, each still taking burstFlowCost beyond
// the free pages the runtime keeps, would take held memory past the door's line.
func burstOver(held, free int64, recent int, at int64) bool {
	grow := int64(recent)*burstFlowCost - free
	return grow > 0 && held+grow >= at*burstLineNum/100
}

var (
	burstMu    sync.Mutex
	burstStart time.Time // start of the current window
	burstPrev  int       // flows let in during the previous window
	burstNow   int       // flows let in during the current one
)

// burstPressed counts a flow at the door and says whether, arriving in a
// burst, it would take the runtime over the valve's line.
func burstPressed() bool {
	at := valveAt.Load()
	if at <= 0 {
		return false
	}
	now := time.Now()
	burstMu.Lock()
	switch since := now.Sub(burstStart); {
	case since >= 2*burstWindow:
		burstStart, burstPrev, burstNow = now, 0, 0
	case since >= burstWindow:
		burstStart, burstPrev, burstNow = burstStart.Add(burstWindow), burstNow, 0
	}
	recent := burstPrev + burstNow
	burstMu.Unlock()
	if recent >= burstFlows {
		// The runtime keeps freed pages up to the soft limit, and new flows
		// fill those first: only what they need beyond them grows the tunnel.
		held, free := goHeldFree()
		if burstOver(held, free, recent, at) {
			return true // not counted: it is not let in (unless as the trickle)
		}
	}
	burstMu.Lock()
	burstNow++
	burstMu.Unlock()
	return false
}

const (
	valveLook     = 250 * time.Millisecond
	valveIdleLook = time.Second
	valveCooldown = time.Second
)

// SetMemoryValve sets the line (bytes the Go runtime holds from the OS) past which
// the core collects and returns free memory at once. Zero or less turns it off.
func SetMemoryValve(bytes int64) {
	valveAt.Store(max(bytes, 0))
	if bytes > 0 {
		valveOnce.Do(func() { go valveLoop() })
	}
}

func goHeld() int64 {
	s := []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}}
	metrics.Read(s)
	return int64(s[0].Value.Uint64() - s[1].Value.Uint64())
}

// goHeldFree is goHeld and, of it, the heap pages the runtime holds free.
func goHeldFree() (held, free int64) {
	s := []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}, {Name: "/memory/classes/heap/free:bytes"}}
	metrics.Read(s)
	return int64(s[0].Value.Uint64() - s[1].Value.Uint64()), int64(s[2].Value.Uint64())
}

func valveLoop() {
	var last time.Time
	for {
		at := valveAt.Load()
		look := valveIdleLook
		if at > 0 {
			held := goHeld()
			if held >= at && time.Since(last) >= valveCooldown {
				debug.FreeOSMemory()
				valveFired.Add(1)
				last = time.Now()
				held = goHeld()
				if held >= at {
					pressedOn.Store(true)
				}
			}
			if held < at*shedClearNum/100 {
				pressedOn.Store(false)
			}
			if held >= at*7/10 {
				look = valveLook
			}
		}
		if at <= 0 {
			pressedOn.Store(false)
		}
		time.Sleep(look)
	}
}
