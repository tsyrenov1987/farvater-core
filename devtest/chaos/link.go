//go:build chaos

package chaos

import (
	"os"
	"strconv"
	"sync"
	"time"
)

// link is the one radio every path shares: a rate all their connections
// split and a round trip every answer waits. A weak cellular signal slows
// every path at once, which no fault set on a single path shows.
type link struct {
	mu   sync.Mutex
	bps  int64
	rtt  time.Duration
	next time.Time
	gone bool // the radio is out: nothing passes until it is back
}

// out takes the radio away (a tunnel, a dead zone) or brings it back. While
// it is out every connection, open or new, waits in silence: no reset tells
// the device, as none does in the field.
func (k *link) out(gone bool) {
	k.mu.Lock()
	k.gone = gone
	k.mu.Unlock()
}

func (k *link) set(bps int64, rtt time.Duration) {
	k.mu.Lock()
	k.bps, k.rtt, k.next = bps, rtt, time.Time{}
	k.mu.Unlock()
}

func (k *link) on() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.bps > 0 || k.gone
}

// delay returns how long n bytes wait: their turn at the shared rate, and a
// round trip when they answer after a pause (last: when this connection last
// sent downstream). A connection holds one chunk in the queue at a time, so
// the connections share the rate evenly.
func (k *link) delay(n int, last time.Time) time.Duration {
	k.mu.Lock()
	for k.gone {
		k.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		k.mu.Lock()
	}
	defer k.mu.Unlock()
	if k.bps <= 0 {
		return 0
	}
	now := time.Now()
	if k.next.Before(now) {
		k.next = now
	}
	w := k.next.Sub(now)
	k.next = k.next.Add(time.Duration(n) * time.Second / time.Duration(k.bps))
	if now.Sub(last) > 100*time.Millisecond {
		w += k.rtt
	}
	return w
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return v
	}
	return def
}
