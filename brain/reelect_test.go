package brain

import "testing"

// The leader trips while the other paths go dark as well (allow lists, a
// block by protocol). The flows that still got through went to a path with a
// short record; a path with a long record has delivered nothing since. The
// new leader is the path that delivered last, not the best record: the app
// would wait on a dark path until its breaker trips too.
func TestTrippedLeaderGoesToThePathThatAnswersNow(t *testing.T) {
	paths := []PathInfo{{ID: "a", SNI: "a.ex", IP: "10.0.0.1"}, {ID: "b", SNI: "b.ex", IP: "10.0.0.2"},
		{ID: "c", SNI: "c.ex", IP: "10.0.0.3"}}
	br := New(DefaultConfig(), "t", paths, 7)
	now := int64(1000)
	br.Pick(now, "x", DstTLS443)
	lead := br.Leader()
	var dark, lit string
	for _, p := range paths {
		if p.ID == lead {
			continue
		}
		if dark == "" {
			dark = p.ID
		} else {
			lit = p.ID
		}
	}
	served := func(p string) {
		r := ok(64 << 10)
		r.Path, r.AtMs, r.DurMs = p, now, 200
		br.Observe(r)
	}
	for i := 0; i < 20; i++ {
		now += 100
		served(lead)
		served(dark)
	}
	now += 2000 // the lists come down: only lit gets through
	for i := 0; i < 2; i++ {
		now += 300
		served(lit)
	}
	for i := 0; i < 2; i++ {
		now += 100
		if ok, sig := br.Breaker.NoteSig(lead, SigHandshake, now); ok {
			br.tripped(lead, sig, now)
		}
	}
	now += 500
	br.Pick(now, "x", DstTLS443)
	if br.Leader() != lit {
		t.Fatalf("leader %s after the trip, want %s, the path that answers now (%v)", br.Leader(), lit, br.J.Entries()[len(br.J.Entries())-1])
	}
}

// With nothing delivered lately the choice stays with the record.
func TestTrippedLeaderWithNothingFreshGoesByRecord(t *testing.T) {
	paths := []PathInfo{{ID: "a", SNI: "a.ex", IP: "10.0.0.1"}, {ID: "b", SNI: "b.ex", IP: "10.0.0.2"},
		{ID: "c", SNI: "c.ex", IP: "10.0.0.3"}}
	br := New(DefaultConfig(), "t", paths, 7)
	now := int64(1000)
	br.Pick(now, "x", DstTLS443)
	lead := br.Leader()
	var good, weak string
	for _, p := range paths {
		if p.ID == lead {
			continue
		}
		if good == "" {
			good = p.ID
		} else {
			weak = p.ID
		}
	}
	served := func(p string) {
		r := ok(64 << 10)
		r.Path, r.AtMs, r.DurMs = p, now, 200
		br.Observe(r)
	}
	for i := 0; i < 10; i++ {
		now += 100
		served(lead)
		served(good)
	}
	now += 100
	served(weak)
	now += 2 * LeadFreshMs
	for i := 0; i < 2; i++ {
		now += 100
		if ok, sig := br.Breaker.NoteSig(lead, SigHandshake, now); ok {
			br.tripped(lead, sig, now)
		}
	}
	br.Pick(now, "x", DstTLS443)
	if br.Leader() != good {
		t.Fatalf("leader %s, want %s by record", br.Leader(), good)
	}
}

// Of the paths that answer now the leader goes to the one that answers
// quickest, not the one that answered last: a shaped path answers too.
func TestTrippedLeaderGoesToTheQuickestOfThoseThatAnswer(t *testing.T) {
	paths := []PathInfo{{ID: "a", SNI: "a.ex", IP: "10.0.0.1"}, {ID: "b", SNI: "b.ex", IP: "10.0.0.2"},
		{ID: "c", SNI: "c.ex", IP: "10.0.0.3"}}
	br := New(DefaultConfig(), "t", paths, 7)
	now := int64(1000)
	br.Pick(now, "x", DstTLS443)
	lead := br.Leader()
	var shaped, fast string
	for _, p := range paths {
		if p.ID == lead {
			continue
		}
		if shaped == "" {
			shaped = p.ID
		} else {
			fast = p.ID
		}
	}
	served := func(p string, answerMs int64) {
		r := ok(64 << 10)
		r.Path, r.AtMs, r.DurMs, r.AnswerMs = p, now, 200, answerMs
		br.Observe(r)
	}
	for i := 0; i < 3; i++ {
		now += 100
		served(fast, 5)
	}
	for i := 0; i < 20; i++ {
		now += 100
		served(lead, 400)
		served(shaped, 500)
	}
	for i := 0; i < 2; i++ {
		now += 100
		if ok, sig := br.Breaker.NoteSig(lead, SigHandshake, now); ok {
			br.tripped(lead, sig, now)
		}
	}
	br.Pick(now, "x", DstTLS443)
	if br.Leader() != fast {
		t.Fatalf("leader %s after the trip, want %s, which answers in 5 ms against 500 (%v)", br.Leader(), fast, br.J.Entries()[len(br.J.Entries())-1])
	}
}

// A keep-alive flow tells its path answers long before its receipt comes.
func TestTrippedLeaderGoesToAPathAnsweringOnAnOpenFlow(t *testing.T) {
	paths := []PathInfo{{ID: "a", SNI: "a.ex", IP: "10.0.0.1"}, {ID: "b", SNI: "b.ex", IP: "10.0.0.2"},
		{ID: "c", SNI: "c.ex", IP: "10.0.0.3"}}
	br := New(DefaultConfig(), "t", paths, 7)
	now := int64(1000)
	br.Pick(now, "x", DstTLS443)
	lead := br.Leader()
	var dark, lit string
	for _, p := range paths {
		if p.ID == lead {
			continue
		}
		if dark == "" {
			dark = p.ID
		} else {
			lit = p.ID
		}
	}
	for i := 0; i < 20; i++ {
		now += 100
		for _, p := range []string{lead, dark} {
			r := ok(64 << 10)
			r.Path, r.AtMs, r.DurMs = p, now, 200
			br.Observe(r)
		}
	}
	now += 3000
	br.NoteAnswered(lit, now-200, now) // still open
	for i := 0; i < 2; i++ {
		now += 100
		if ok, sig := br.Breaker.NoteSig(lead, SigHandshake, now); ok {
			br.tripped(lead, sig, now)
		}
	}
	br.Pick(now, "x", DstTLS443)
	if br.Leader() != lit {
		t.Fatalf("leader %s after the trip, want %s, answering on an open flow", br.Leader(), lit)
	}
}
