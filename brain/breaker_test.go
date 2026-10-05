package brain

import "testing"

func deliv(path string, at int64) Receipt {
	return Receipt{Path: path, Ctx: "t", AtMs: at, WireReadyMs: 20, FirstByteMs: 30, Down: 64 * KB, DownAtFail: -1, End: EndRemoteFin, Dst: "h"}
}
func reset(path string, at int64) Receipt {
	return Receipt{Path: path, Ctx: "t", AtMs: at, WireReadyMs: 20, FirstByteMs: 30, Down: 10 * KB, DownAtFail: 10 * KB, End: EndWireReset, Dst: "h"}
}
func blackhole(path string, at int64) Receipt {
	return Receipt{Path: path, Ctx: "t", AtMs: at, WireReadyMs: 20, FirstByteMs: -1, DownAtFail: -1, End: EndTimeout, Dst: "h"}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		r   Receipt
		sig BlockSig
	}{
		{reset("p", 0), SigReset},
		{blackhole("p", 0), SigBlackhole},
		{Receipt{WireReadyMs: -1, FirstByteMs: -1, End: EndTimeout, DownAtFail: -1}, SigHandshake},
		{Receipt{WireReadyMs: 20, FirstByteMs: 30, End: EndStallAbandon, Down: 16 * KB, DownAtFail: 16 * KB}, SigThrottle},
		{deliv("p", 0), SigNone},
	}
	for i, c := range cases {
		if got := classify(c.r); got != c.sig {
			t.Errorf("case %d: classify=%v want %v", i, got, c.sig)
		}
	}
}

func TestBreakerTripsOnOneReset(t *testing.T) {
	b := NewBreaker(DefaultBreakerConfig())
	tripped, sig := b.Note(reset("p", 1000), 1000)
	if !tripped || sig != SigReset {
		t.Fatalf("one reset must trip: tripped=%v sig=%v", tripped, sig)
	}
	if !b.Tripped("p", 1000) || !b.Tripped("p", 1000+89_000) {
		t.Fatal("rail should stay tripped through the reset cooldown")
	}
	if b.Tripped("p", 1000+91_000) {
		t.Fatal("rail must auto-recover after the cooldown (no permanent removal)")
	}
}

func TestBreakerSoftNeedsTwo(t *testing.T) {
	b := NewBreaker(DefaultBreakerConfig())
	if tripped, _ := b.Note(blackhole("p", 0), 0); tripped {
		t.Fatal("one blackhole must not trip")
	}
	if tripped, _ := b.Note(blackhole("p", 5_000), 5_000); !tripped {
		t.Fatal("two blackholes inside the window must trip")
	}
}

func TestBreakerSoftWindowExpiry(t *testing.T) {
	b := NewBreaker(DefaultBreakerConfig())
	b.Note(blackhole("p", 0), 0)
	// Second blackhole far outside the window: the first is forgotten, no trip.
	if tripped, _ := b.Note(blackhole("p", 120_000), 120_000); tripped {
		t.Fatal("soft signals outside the window must not accumulate")
	}
}

func TestBreakerStormNeedsDistinctRails(t *testing.T) {
	b := NewBreaker(DefaultBreakerConfig())
	b.Note(reset("p", 0), 0)
	if b.Storm(10) {
		t.Fatal("one tripped rail is not a storm")
	}
	b.Note(reset("q", 100), 100)
	if !b.Storm(200) {
		t.Fatal("two tripped rails inside the window is a storm")
	}
}

func TestLeaderTripDethronesImmediately(t *testing.T) {
	paths := []PathInfo{{ID: "A", SNI: "a", IP: "1", Rail: "reality"}, {ID: "B", SNI: "b", IP: "2", Rail: "xhttp"}, {ID: "C", SNI: "c", IP: "3", Rail: "ws"}}
	b := New(DefaultConfig(), "t", paths, 1)
	now := int64(0)
	// Establish A as a well-proven leader.
	for i := 0; i < 8; i++ {
		b.Pick(now, "h", DstTLS443)
		b.Observe(deliv("A", now))
		now += 1000
	}
	if b.Leader() != "A" {
		t.Fatalf("A should lead, got %q", b.Leader())
	}
	// A single reset on A must dethrone it on the very next pick, without the
	// usual 5-receipt / 2-stall hysteresis.
	b.Observe(reset("A", now))
	if b.Leader() != "" && b.Leader() == "A" {
		t.Fatal("reset on the leader should have cleared it")
	}
	d := b.Pick(now, "h", DstTLS443)
	if d.Primary == "A" {
		t.Fatalf("tripped rail must not be primary, got %s", d.Primary)
	}
	if b.J.Count("lead_trip") < 1 {
		t.Fatal("a lead_trip should be journalled")
	}
}

func TestDiverseEscapePrefersUnlikeSibling(t *testing.T) {
	paths := []PathInfo{
		{ID: "P", SNI: "s1", IP: "1", Rail: "reality"},
		{ID: "Q", SNI: "s1", IP: "1", Rail: "reality"}, // identical axes: a sibling
		{ID: "R", SNI: "s2", IP: "2", Rail: "xhttp"},   // unlike on every axis
	}
	b := New(DefaultConfig(), "t", paths, 1)
	got := b.bestEscape([]string{"P", "Q", "R"}, []string{"P"}, b.info("P"), 0)
	if got != "R" {
		t.Fatalf("escape should prefer the diverse rail R, got %s", got)
	}
}
