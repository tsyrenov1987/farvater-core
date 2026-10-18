package brain

import "testing"

// Android resets a cached app's sockets as it blocks its network and tells the
// app a moment later; a push gives the network back. Neither the resets nor
// what fails while the network is blocked may trip the rails: the push is for
// a call, and its first request must not find every path avoided.
func TestBlockedNetworkIsNotEvidence(t *testing.T) {
	paths := []PathInfo{{ID: "A", SNI: "a", IP: "1", Rail: "reality"}, {ID: "B", SNI: "b", IP: "2", Rail: "xhttp"}}
	b := New(DefaultConfig(), "t", paths, 1)
	now := int64(0)
	for i := 0; i < 8; i++ {
		b.Pick(now, "h", DstTLS443)
		b.Observe(deliv("A", now))
		now += 1000
	}
	if b.Leader() != "A" {
		t.Fatalf("A should lead, got %q", b.Leader())
	}

	// the resets land just before the app hears of the block
	b.Observe(reset("A", now))
	b.Observe(reset("B", now))
	b.Blocked(now + 5)
	before := b.State("B")
	b.Observe(blackhole("B", now+10_000))
	b.Observe(blackhole("B", now+11_000))
	b.Unblocked(now + 20_000)
	late := blackhole("A", now+24_000)
	late.DurMs = 6000 // begun while the network was blocked
	b.Observe(late)

	at := now + 24_000
	if after := b.State("B"); after.Blocked != before.Blocked {
		t.Fatalf("flows failed while the network was blocked counted against B: blocked %d→%d", before.Blocked, after.Blocked)
	}
	if b.Breaker.Tripped("A", at) || b.Breaker.Tripped("B", at) || b.Breaker.Storm(at) {
		t.Fatalf("the block tripped the rails: A %v, B %v, storm %v", b.Breaker.Tripped("A", at), b.Breaker.Tripped("B", at), b.Breaker.Storm(at))
	}
	if d := b.Pick(at, "h", DstTLS443); d.Primary != "A" {
		t.Fatalf("after the block the first flow goes to %q, want the leader A", d.Primary)
	}

	// a reset with the network up still trips at once
	b.Observe(reset("A", at+1000))
	if !b.Breaker.Tripped("A", at+1000) {
		t.Fatal("a reset after the block did not trip the rail")
	}
}
