package brain

import (
	"math"
	"math/rand/v2"
	"testing"
)

func TestBetaSampleMean(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	sum := 0.0
	const n = 20000
	for range n {
		sum += BetaSample(rng, 8, 2)
	}
	if m := sum / n; math.Abs(m-0.8) > 0.02 {
		t.Fatalf("Beta(8,2) mean %.3f, want 0.8", m)
	}
}

func ok(down int64) Receipt {
	return Receipt{WireReadyMs: 30, FirstByteMs: 50, Down: down, End: EndRemoteFin, DownAtFail: -1}
}
func stalled(at int64) Receipt {
	return Receipt{WireReadyMs: 30, FirstByteMs: 50, Down: at, DownAtFail: at, Stalls: 1, End: EndStallAbandon}
}

func TestCut16Detection(t *testing.T) {
	s := &PathState{}
	now := int64(1)
	for _, kb := range []int64{17, 19, 21} {
		s.Observe(stalled(kb*KB), now, 600_000)
		now += 1000
	}
	if !s.Cut16 {
		t.Fatalf("cut16 not set after stalls at 17/19/21 KB")
	}
	for range 3 {
		s.Observe(ok(100*KB), now, 600_000)
		now += 1000
	}
	if s.Cut16 {
		t.Fatalf("cut16 not cleared after three ≥64 KB deliveries")
	}
}

func TestDecayHalvesEvidence(t *testing.T) {
	s := &PathState{}
	for i := range 4 {
		s.Observe(ok(100*KB), int64(1+i), 600_000)
	}
	s.decay(600_004, 600_000)
	if math.Abs(s.evDelivA-2) > 0.01 {
		t.Fatalf("evidence after one half-life %.3f, want 2", s.evDelivA)
	}
}

func TestGovernorPacing(t *testing.T) {
	g := NewGovernor()
	var ts []int64
	for range 10 {
		ts = append(ts, g.Acquire("s", "ip", 0))
	}
	for i := range ts {
		n400, n1000 := 0, 0
		for j := range ts {
			if ts[j] >= ts[i] && ts[j] < ts[i]+400 {
				n400++
			}
			if ts[j] >= ts[i] && ts[j] < ts[i]+1000 {
				n1000++
			}
		}
		if n400 > 2 || n1000 > 4 {
			t.Fatalf("pacing violated at %d: %d/400ms %d/1s (%v)", ts[i], n400, n1000, ts)
		}
		if i > 0 && ts[i] < ts[i-1] {
			t.Fatalf("slots not monotonic: %v", ts)
		}
	}
}

func TestLeaderHysteresis(t *testing.T) {
	paths := []PathInfo{{ID: "A", SNI: "a", IP: "1"}, {ID: "B", SNI: "b", IP: "2"}, {ID: "C", SNI: "c", IP: "3"}}
	b := New(DefaultConfig(), "t", paths, 1)
	b.Pick(1000, "h", DstTLS443)
	if b.Leader() != "A" {
		t.Fatalf("initial leader %q, want A (first in order)", b.Leader())
	}
	feed := func(path string, okN, badN int, at int64) {
		// interleave so that no two stalls are consecutive (that is the separate stall rule)
		i := 0
		for okN > 0 || badN > 0 {
			var r Receipt
			if okN > 0 {
				r = ok(100 * KB)
				okN--
			} else {
				r = stalled(18 * KB)
				badN--
			}
			r.Path, r.AtMs = path, at+int64(i)
			b.Observe(r)
			i++
			if badN > 0 && okN > 0 {
				r = stalled(18 * KB)
				r.Path, r.AtMs = path, at+int64(i)
				b.Observe(r)
				badN--
				i++
			}
		}
	}
	feed("A", 6, 4, 2000) // mean ≈ 0.54
	feed("C", 7, 3, 2000) // mean ≈ 0.61: not enough margin
	b.Pick(3000, "h", DstTLS443)
	if b.Leader() != "A" {
		t.Fatalf("weak challenger dethroned the leader: %q", b.Leader())
	}
	feed("B", 9, 1, 2000) // mean ≈ 0.76: beats A by > 0.15
	b.Pick(4000, "h", DstTLS443)
	if b.Leader() != "B" {
		t.Fatalf("leader %q, want B after a clear challenger", b.Leader())
	}
	if b.J.Count("lead_switch") != 1 {
		t.Fatalf("journal: %d lead_switch entries, want 1", b.J.Count("lead_switch"))
	}
}

func TestServedAndBlockedCounts(t *testing.T) {
	var s PathState
	s.Observe(deliv("p", 1000), 1000, 60_000)
	s.Observe(reset("p", 2000), 2000, 60_000)
	s.Observe(blackhole("p", 3000), 3000, 60_000)
	// Closed by the client before any answer: no evidence either way.
	quiet := Receipt{Path: "p", AtMs: 4000, WireReadyMs: 20, FirstByteMs: -1, DownAtFail: -1, End: EndLocalClose}
	s.Observe(quiet, 4000, 60_000)
	if s.Receipts != 4 || s.Served != 1 || s.Blocked != 2 {
		t.Fatalf("receipts=%d served=%d blocked=%d, want 4/1/2", s.Receipts, s.Served, s.Blocked)
	}
}
