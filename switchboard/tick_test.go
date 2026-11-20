package switchboard

import (
	"sync"
	"testing"
	"time"
)

// Flows that began at different moments tick on the same beats.
func TestWatchdogsTickOnOneBeat(t *testing.T) {
	for _, c := range []struct{ now, period, want int64 }{
		{1000, 1000, 1000}, {1001, 1000, 999}, {1999, 1000, 1}, {1250, 250, 250}, {1251, 250, 249}, {1499, 250, 1},
	} {
		if got := untilTick(c.now, c.period).Milliseconds(); got != c.want {
			t.Errorf("untilTick(%d, %d) = %d ms, want %d", c.now, c.period, got, c.want)
		}
	}
	// Thirty watchdogs started 7 ms apart all fire within one beat's few ms.
	const n, period = 30, 250
	var mu sync.Mutex
	var fired []int64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tm := time.NewTimer(untilTick(nowMs(), period))
			<-tm.C
			tm.Reset(untilTick(nowMs(), period))
			<-tm.C
			mu.Lock()
			fired = append(fired, time.Now().UnixMilli())
			mu.Unlock()
		}()
		time.Sleep(7 * time.Millisecond)
	}
	wg.Wait()
	lo, hi := fired[0], fired[0]
	for _, f := range fired {
		lo, hi = min(lo, f), max(hi, f)
	}
	// Those started just before a beat fire one beat earlier than the rest.
	spread := (hi - lo) % period
	if spread > period/2 {
		spread = period - spread
	}
	t.Logf("%d watchdogs started over %d ms fired %d ms apart, beats aside", n, n*7, spread)
	if spread > 50 {
		t.Fatalf("the watchdogs fired %d ms apart: they do not share a beat", spread)
	}
}
