package brain

import "testing"

func TestHsStepLadder(t *testing.T) {
	for _, c := range []struct {
		gap  int64
		want int
	}{{-1, 0}, {0, 1}, {999, 1}, {1000, 2}, {1999, 2}, {2000, 3}, {9999, 3}, {10_000, 4}, {59_999, 4}, {60_000, 5}, {120_000, 6}, {599_999, 6}, {600_000, 7}, {1 << 40, 7}} {
		if got := HsStep(c.gap); got != c.want {
			t.Errorf("HsStep(%d) = %d, want %d", c.gap, got, c.want)
		}
	}
}

func TestHandshakeCountedOnlyAsEvidence(t *testing.T) {
	paths := []PathInfo{{ID: "a", SNI: "a.example", IP: "192.0.2.1"}, {ID: "b", SNI: "b.example", IP: "192.0.2.2"}}
	b := New(DefaultConfig(), "wifi", paths, 1)
	now := int64(1_000_000)

	b.NoteHandshake("a", -1, HsOK, now)
	b.NoteHandshake("a", 300, HsFail, now)
	b.NoteHandshake("a", 1500, HsTimeout, now)
	b.NoteHandshake("a", 700_000, HsOK, now)
	b.NoteHandshake("nope", 300, HsFail, now) // not a path
	s := b.State("a")
	if s.HsOK != (HsHist{0: 1, 7: 1}) || s.HsFail != (HsHist{1: 1}) || s.HsTimeout != (HsHist{2: 1}) {
		t.Fatalf("ok %v fail %v timeout %v", s.HsOK, s.HsFail, s.HsTimeout)
	}
	if s := b.State("b"); s.HsOK != (HsHist{}) || s.HsFail != (HsHist{}) {
		t.Fatalf("path b made no handshake, yet: %v %v", s.HsOK, s.HsFail)
	}

	b.Blocked(now + 200)
	b.NoteHandshake("a", 300, HsFail, now+300)
	b.NoteHandshake("a", 300, HsOK, now+300)
	s = b.State("a")
	if s.HsFail != (HsHist{1: 1}) {
		t.Fatalf("a failure counted while the system blocks the app's network: %v", s.HsFail)
	}
	if s.HsOK != (HsHist{0: 1, 1: 1, 7: 1}) {
		t.Fatalf("a handshake that completed was not counted: %v", s.HsOK)
	}
}
