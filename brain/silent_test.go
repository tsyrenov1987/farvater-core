package brain

import "testing"

func dialTimeout(path string, at int64) Receipt {
	return Receipt{Path: path, AtMs: at, DurMs: 8000, WireReadyMs: -1, FirstByteMs: -1, DownAtFail: -1, End: EndTimeout, Dst: "h"}
}

func served(path string, at int64) Receipt {
	r := ok(8 << 10)
	r.Path, r.AtMs, r.DurMs, r.AnswerMs = path, at, 100, 200
	return r
}

// The radio goes silent for twelve seconds every twenty: no SYN is answered
// on any path, no RST comes. The dials of the leader and of the path raced
// with it time out in each gap, two a minute and more. They are held, the
// paths connect when the radio is back and the held dials are forgotten: no
// path trips and the lead stays where it was.
func TestRadioGapsDoNotTripTheLeader(t *testing.T) {
	paths := sweepPaths()
	br := New(DefaultConfig(), "cell", paths, 1)
	now := warm(br, paths, 0)
	br.Pick(now, "h", DstTLS443)
	lead := br.Leader()
	other := "b"
	if lead == "b" {
		other = "a"
	}
	for gap := 0; gap < 5; gap++ {
		now += 9000 // the gap began a second after the last answer
		br.Observe(dialTimeout(lead, now))
		br.Observe(dialTimeout(lead, now+300))
		br.Observe(dialTimeout(other, now+600))
		now += 4000 // the radio is back
		br.Observe(served(lead, now))
		br.Observe(served(other, now+50))
		now += 9000
		br.Pick(now, "h", DstTLS443)
		if br.Breaker.Tripped(lead, now) || br.Breaker.Tripped(other, now) {
			t.Fatalf("gap %d: a path tripped on the radio's silence", gap)
		}
		if br.Leader() != lead {
			t.Fatalf("gap %d: the lead went from %s to %s", gap, lead, br.Leader())
		}
	}
}

// A path shut while the network is up is counted as before: with another
// path delivering during its dials, at once; with the next path taking the
// flow right after each timeout, as soon as that one's receipt is in.
func TestAShutPathStillTrips(t *testing.T) {
	for _, overlap := range []bool{true, false} {
		paths := sweepPaths()
		br := New(DefaultConfig(), "cell", paths, 1)
		now := warm(br, paths, 0)
		for i := 0; i < 2; i++ {
			now += 9000
			if overlap {
				br.Observe(served("b", now-4000)) // b answered while a's dial was out
			}
			br.Observe(dialTimeout("a", now))
			if !overlap {
				r := served("b", now+150) // the flow went on over b and connected at once
				br.Observe(r)
			}
		}
		if !br.Breaker.Tripped("a", now+200) {
			t.Fatalf("overlap %v: a path shut on a live network did not trip on its second timeout", overlap)
		}
	}
}

// A path with no connection to its name is not held: its first timeouts
// count at once.
func TestAPathThatNeverConnectedIsNotHeld(t *testing.T) {
	paths := sweepPaths()
	br := New(DefaultConfig(), "cell", paths, 1)
	br.Observe(dialTimeout("a", 9000))
	if len(br.Diag.held) != 0 {
		t.Fatal("a path that never connected was held")
	}
}
