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
)

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
			}
			if held >= at*7/10 {
				look = valveLook
			}
		}
		time.Sleep(look)
	}
}
