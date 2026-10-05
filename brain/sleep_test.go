package brain

import "testing"

// A phone that sleeps through a flow loses it whatever the path: NAT mappings
// expire and the radio goes quiet. Such a receipt must not count against the
// path, while a flow over a nap shorter than the grace still does.
func TestSleptFlowIsNotEvidence(t *testing.T) {
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
	before := b.State("A")

	slept := reset("A", now)
	slept.SleptMs = 60_000
	b.Observe(slept)
	if b.Leader() != "A" || b.J.Count("lead_trip") != 0 {
		t.Fatalf("a flow cut by the phone's sleep dethroned the leader (leader %q)", b.Leader())
	}
	if after := b.State("A"); after.Blocked != before.Blocked || after.DelivMean() != before.DelivMean() {
		t.Fatalf("a slept flow changed A's evidence: blocked %d→%d, deliv %.3f→%.3f", before.Blocked, after.Blocked, before.DelivMean(), after.DelivMean())
	}
	if b.Dropped != 1 || b.J.Count("drop_sleep") != 1 {
		t.Fatalf("dropped %d, drop_sleep %d; want 1 and 1", b.Dropped, b.J.Count("drop_sleep"))
	}

	nap := reset("A", now+1000)
	nap.SleptMs = SleepGraceMs - 1
	b.Observe(nap)
	if b.J.Count("lead_trip") != 1 {
		t.Fatal("a reset over a nap shorter than the grace must still count")
	}
}
