package brain

import "testing"

// Allow-lists on: in the restricted network every path stays silent a while
// and the breaker trips them all, the path entering through an allow-listed
// address too, before the lists let it through. It is the one meant to pass
// in a restricted network: it leads at once, not after its cooldown runs out
// or the other trips age.
func TestRestrictedNetworkLeadsWithTheWhitePath(t *testing.T) {
	paths := []PathInfo{{ID: "a", SNI: "a.ex", IP: "10.0.0.1"}, {ID: "b", SNI: "b.ex", IP: "10.0.0.2"},
		{ID: "w", SNI: "w.ex", IP: "10.0.0.3", White: true}}
	br := New(DefaultConfig(), "cell", paths, 7)
	now := int64(1000)
	br.Pick(now, "x", DstTLS443)
	trip := func(p string) {
		for i := 0; i < 2; i++ {
			if ok, sig := br.Breaker.NoteSig(p, SigHandshake, now); ok {
				br.tripped(p, sig, now)
			}
		}
	}
	now += 1000
	br.EnterRestricted(now)
	now += 1000
	trip("a")
	now += 1000
	trip("b")
	now += 1000
	trip("w")
	for i := 0; i < 3; i++ {
		now += 100
		br.Pick(now, "x", DstTLS443)
		if br.Leader() != "w" {
			t.Fatalf("pick %d in the restricted network: leader %q, want the white path w", i, br.Leader())
		}
	}
}
