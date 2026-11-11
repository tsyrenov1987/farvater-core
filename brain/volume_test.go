package brain

import "testing"

func TestVolStepLadder(t *testing.T) {
	for _, c := range []struct {
		n    int64
		step int
	}{
		{0, 0}, {4*KB - 1, 0}, {4 * KB, 1}, {12*KB - 1, 1}, {12 * KB, 2}, {20 * KB, 2}, {28 * KB, 3},
		{256*KB - 1, 3}, {256 * KB, 4}, {4 << 20, 5}, {32 << 20, 6}, {128 << 20, 7}, {1 << 40, 7},
	} {
		if got := VolStep(c.n); got != c.step {
			t.Errorf("VolStep(%d) = %d, want %d", c.n, got, c.step)
		}
	}
}

// A flow that had its first byte is counted once, by how it ended and at what
// volume; one that never had an answer is not a matter of volume.
func TestFlowEndsCountedByVolume(t *testing.T) {
	s := &PathState{}
	reset := Receipt{WireReadyMs: 30, FirstByteMs: 50, Down: 5 << 20, DownAtFail: 5 << 20, End: EndWireReset}
	silent := Receipt{WireReadyMs: 30, FirstByteMs: -1, DownAtFail: 0, End: EndTimeout}
	now := int64(1)
	for _, r := range []Receipt{ok(100 * KB), ok(2 * KB), stalled(20 * KB), stalled(18 * KB), reset, silent} {
		s.Observe(r, now, 600_000)
		now += 1000
	}
	if want := (VolHist{0: 1, 3: 1}); s.Ended != want {
		t.Errorf("ended %v, want %v", s.Ended, want)
	}
	if want := (VolHist{2: 2}); s.CutStall != want {
		t.Errorf("cut by a stall %v, want %v", s.CutStall, want)
	}
	if want := (VolHist{5: 1}); s.CutReset != want {
		t.Errorf("cut by a reset %v, want %v", s.CutReset, want)
	}
}

// A shared connection's end is counted by kind and volume, and only where a
// flow would be evidence: not one the device slept through, not one made on
// the network it has left, not while the system keeps the app off the network.
func TestConnEndCountedOnlyAsEvidence(t *testing.T) {
	paths := []PathInfo{{ID: "a", SNI: "a.example", IP: "192.0.2.1"}, {ID: "b", SNI: "b.example", IP: "192.0.2.2"}}
	b := New(DefaultConfig(), "wifi", paths, 1)
	now := int64(1_000_000)

	b.NoteConnEnd("a", ConnDead, 20*KB, now-5000, 0, now)
	b.NoteConnEnd("a", ConnReset, 8<<20, now-5000, 0, now)
	b.NoteConnEnd("a", ConnFin, 300*KB, now-5000, 0, now)
	b.NoteConnEnd("a", ConnOurs, 200<<20, now-5000, 0, now)
	b.NoteConnEnd("a", ConnDead, 20*KB, now-5000, SleepGraceMs, now) // slept through
	b.NoteConnEnd("nope", ConnDead, 20*KB, now-5000, 0, now)         // not a path
	s := b.State("a")
	if s.ConnDead != (VolHist{2: 1}) || s.ConnReset != (VolHist{5: 1}) || s.ConnFin != (VolHist{4: 1}) || s.ConnOurs != (VolHist{7: 1}) {
		t.Fatalf("dead %v reset %v fin %v ours %v", s.ConnDead, s.ConnReset, s.ConnFin, s.ConnOurs)
	}

	b.SwitchContext("cell", now)
	b.NoteConnEnd("a", ConnReset, 20*KB, now-5000, 0, now+100) // made on the network left
	if s := b.State("a"); s.ConnReset != (VolHist{}) {
		t.Fatalf("a connection of the network left was counted on the new one: %v", s.ConnReset)
	}
	b.NoteConnEnd("a", ConnReset, 20*KB, now+50, 0, now+100)
	if s := b.State("a"); s.ConnReset != (VolHist{2: 1}) {
		t.Fatalf("a connection of this network was not counted: %v", s.ConnReset)
	}

	b.Blocked(now + 200)
	b.NoteConnEnd("a", ConnDead, 20*KB, now+60, 0, now+300)
	if s := b.State("a"); s.ConnDead != (VolHist{}) {
		t.Fatalf("counted while the system blocks the app's network: %v", s.ConnDead)
	}
}
