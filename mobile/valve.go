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
	if !pressedOn.Load() {
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
