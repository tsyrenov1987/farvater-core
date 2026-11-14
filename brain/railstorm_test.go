package brain

import "testing"

// 14.11.2026: the flows on one h2 connection end together when it dies, each
// with a reset receipt. One rail is one trip: its dead socket is no storm.
// A second rail tripping is.
func TestOneRailsResetsAreNoStorm(t *testing.T) {
	b := NewBreaker(DefaultConfig().Breaker)
	now := int64(1000)
	for range 16 {
		b.NoteSig("x1", SigReset, now)
		now += 5
	}
	if b.Storm(now) {
		t.Fatal("sixteen resets on one rail raised a storm")
	}
	if !b.Tripped("x1", now) {
		t.Fatal("the rail did not trip")
	}
	if tripped, _ := b.NoteSig("g2", SigReset, now); !tripped || !b.Storm(now) {
		t.Fatal("a second rail's trip raised no storm")
	}
}
