package vkturn

import (
	"sync"
	"time"
)

// pacer is a token bucket in bytes. VK polices each relay allocation at
// about 2 Mbit/s and drops the excess, so we stay under it ourselves.
type pacer struct {
	mu     sync.Mutex
	rate   float64 // bytes per second
	burst  float64
	tokens float64
	last   time.Time
}

func newPacer(bitsPerSec int) *pacer {
	r := float64(bitsPerSec) / 8
	return &pacer{rate: r, burst: r / 10, tokens: r / 10, last: time.Now()}
}

func (p *pacer) refill(now time.Time) {
	p.tokens += now.Sub(p.last).Seconds() * p.rate
	if p.tokens > p.burst {
		p.tokens = p.burst
	}
	p.last = now
}

// level reports the tokens available now.
func (p *pacer) level() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refill(time.Now())
	return p.tokens
}

// take spends n bytes, sleeping until the bucket allows it.
func (p *pacer) take(n int) {
	p.mu.Lock()
	p.refill(time.Now())
	p.tokens -= float64(n)
	wait := time.Duration(0)
	if p.tokens < 0 {
		wait = time.Duration(-p.tokens / p.rate * float64(time.Second))
	}
	p.mu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
}
