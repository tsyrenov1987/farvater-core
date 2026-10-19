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

// Cold start on a mobile network: until the leader answers, every flow also
// dials the allow-listed path, so where the lists silence the rest the first
// flow does not wait out silent dials. On Wi-Fi a mobile-only white path is
// not dialed so, and once the leader answers it is not either.
func TestWhitePathJoinsTheFirstDialsUntilTheLeaderAnswers(t *testing.T) {
	paths := []PathInfo{{ID: "a", SNI: "a.ex", IP: "10.0.0.1"}, {ID: "b", SNI: "b.ex", IP: "10.0.0.2"},
		{ID: "c", SNI: "c.ex", IP: "10.0.0.4"}, {ID: "w", SNI: "w.ex", IP: "10.0.0.3", White: true, Net: "cell"}}
	br := New(DefaultConfig(), "cell", paths, 7)
	now := int64(1000)
	d := br.Pick(now, "x", DstTLS443)
	if d.Primary != "w" && d.Secondary != "w" && d.Tertiary != "w" {
		t.Fatalf("cold start on cell: dials %q %q %q, want the white path w among them", d.Primary, d.Secondary, d.Tertiary)
	}
	wifi := New(DefaultConfig(), "wifi:home", paths, 7)
	if d := wifi.Pick(now, "x", DstTLS443); d.Tertiary == "w" {
		t.Fatalf("cold start on Wi-Fi: the mobile-only white path dialed third")
	}
	if l := br.Leader(); l != "w" {
		br.NoteAnswered(l, now, now+200)
		if d := br.Pick(now+300, "x", DstTLS443); d.Tertiary == "w" {
			t.Fatalf("leader %s answers: the white path still dialed third", l)
		}
	}
}
