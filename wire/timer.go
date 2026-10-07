package wire

import (
	"sync"
	"sync/atomic"
	"time"
)

// idleTimer ends a flow once neither direction has carried a byte for its
// timeout. touch only records the time, so it is cheap enough to call for
// every chunk; the timer itself wakes at most once per timeout and sleeps
// again for whatever is left.
type idleTimer struct {
	start  time.Time
	last   atomic.Int64 // nanoseconds after start of the last traffic
	cancel func()

	mu      sync.Mutex
	timeout time.Duration
	t       *time.Timer
}

func newIdleTimer(timeout time.Duration, cancel func()) *idleTimer {
	it := &idleTimer{start: time.Now(), cancel: cancel, timeout: timeout}
	it.t = time.AfterFunc(timeout, it.fire)
	return it
}

func (it *idleTimer) since() time.Duration { return time.Since(it.start) }

// touch records traffic.
func (it *idleTimer) touch() { it.last.Store(int64(it.since())) }

func (it *idleTimer) fire() {
	it.mu.Lock()
	left := it.timeout - (it.since() - time.Duration(it.last.Load()))
	if left > 0 {
		it.t.Reset(left)
		it.mu.Unlock()
		return
	}
	it.mu.Unlock()
	it.cancel()
}

// setTimeout replaces the timeout, counted from now.
func (it *idleTimer) setTimeout(d time.Duration) {
	it.mu.Lock()
	defer it.mu.Unlock()
	it.timeout = d
	it.touch()
	it.t.Reset(d)
}

func (it *idleTimer) stop() { it.t.Stop() }
