package brain

import "testing"

func sweepPaths() []PathInfo {
	var paths []PathInfo
	for i, id := range []string{"a", "b", "c", "d", "e", "f"} {
		paths = append(paths, PathInfo{ID: id, SNI: id + ".ex", IP: "10.0.0." + string(rune('1'+i))})
	}
	return paths
}

// warm gives every path a record of pages served, as a session's first
// minutes do, and returns the time after.
func warm(br *Brain, paths []PathInfo, now int64) int64 {
	for i := 0; i < 10; i++ {
		for _, p := range paths {
			now += 50
			r := ok(8 << 10)
			r.Path, r.AtMs, r.DurMs, r.AnswerMs = p.ID, now, 100, 200
			br.Observe(r)
		}
	}
	return now
}

func trip(br *Brain, path string, now int64) {
	for i := 0; i < 2; i++ {
		if ok, sig := br.Breaker.NoteSig(path, SigReset, now); ok {
			br.tripped(path, sig, now)
		}
	}
}

// The leader trips. Every path answers pages alike; only one delivers a
// download whole. Picks alone go by record to some path that resets
// downloads, and the app's next download learns it. A sweep probes the
// available paths at once, and the leader goes to the one that delivered
// the probe within a second, the app's flows untouched.
func TestSweepHandsTheLeadToThePathThatDeliversTheProbe(t *testing.T) {
	paths := sweepPaths()
	br := New(DefaultConfig(), "t", paths, 7)
	now := warm(br, paths, 1000)
	br.Pick(now, "x", DstTLS443)
	lead := br.Leader()
	trip(br, lead, now)
	probed := br.SweepDue(now)
	if len(probed) != len(paths)-1 {
		t.Fatalf("the leader tripped: sweep of %v, want the %d available paths", probed, len(paths)-1)
	}
	br.Pick(now+1, "x", DstTLS443) // re-elected by record meanwhile
	fast := probed[len(probed)-1]
	if fast == br.Leader() {
		fast = probed[0]
	}
	br.Swept(fast, 256<<10, 40, true, now+40)
	for _, p := range probed {
		if p != fast && p != br.Leader() {
			br.Swept(p, 48<<10, 3000, false, now+3000)
			break
		}
	}
	for at := now + 100; at <= now+1100; at += 100 {
		br.SweepCheck(at)
	}
	if br.Leader() != fast {
		t.Fatalf("leader %s a second after the sweep, want %s, the path that delivered the probe whole in 40 ms (%v)", br.Leader(), fast, br.J.Entries()[len(br.J.Entries())-1])
	}
}

// Two healthy paths a little apart: the leader keeps the lead.
func TestSweepKeepsALeaderThatHoldsItsOwn(t *testing.T) {
	paths := sweepPaths()
	br := New(DefaultConfig(), "t", paths, 7)
	now := warm(br, paths, 1000)
	br.Pick(now, "x", DstTLS443)
	trip(br, br.Leader(), now)
	probed := br.SweepDue(now)
	br.Pick(now+1, "x", DstTLS443)
	lead := br.Leader()
	for _, p := range probed {
		ms := int64(300)
		if p == lead {
			ms = 600
		}
		br.Swept(p, 256<<10, ms, true, now+ms)
	}
	br.SweepCheck(now + 5000)
	if br.Leader() != lead {
		t.Fatalf("leader moved %s → %s over 300 ms against 600: noise between healthy paths", lead, br.Leader())
	}
}

// No doubt, no sweep: a leader that delivers costs no probes. A doubt the
// interval holds back is swept once the interval is out, unless the next
// leader answers by then.
func TestSweepOnlyInDoubtAndNotTooOften(t *testing.T) {
	paths := sweepPaths()
	br := New(DefaultConfig(), "t", paths, 7)
	now := warm(br, paths, 1000)
	br.Pick(now, "x", DstTLS443)
	if p := br.SweepDue(now); p != nil {
		t.Fatalf("swept %v with the leader delivering", p)
	}
	trip(br, br.Leader(), now)
	if br.SweepDue(now) == nil {
		t.Fatal("no sweep when the leader tripped")
	}
	for _, p := range br.sw.paths() {
		br.Swept(p, 256<<10, 100, true, now+100)
	}
	br.Pick(now+200, "x", DstTLS443)
	now += 1000
	trip(br, br.Leader(), now)
	if p := br.SweepDue(now); p != nil {
		t.Fatalf("a second sweep %d ms after the first: %v", 1000, p)
	}
	now += DefaultConfig().SweepMs
	if br.SweepDue(now) == nil {
		t.Fatal("the held back doubt was not swept once the interval was out")
	}
	for _, p := range br.sw.paths() {
		br.Swept(p, 256<<10, 100, true, now+100)
	}
	now += DefaultConfig().SweepMs
	trip(br, br.Leader(), now)
	br.Pick(now+1, "x", DstTLS443)
	r := ok(8 << 10)
	r.Path, r.AtMs, r.DurMs = br.Leader(), now+300, 100
	br.Observe(r)
	if p := br.SweepDue(now + 400); p != nil {
		t.Fatalf("swept %v though the next leader answers", p)
	}
}

// A slow leader has the paths with no goodput of their own swept, itself
// with them, and none twice while their measure is fresh.
func TestSweepOfASlowLeaderTakesTheUnmeasured(t *testing.T) {
	paths := sweepPaths()
	br := New(DefaultConfig(), "t", paths, 7)
	now := warm(br, paths, 1000)
	br.Pick(now, "x", DstTLS443)
	lead := br.Leader()
	measured := ""
	for _, p := range paths {
		if p.ID != lead {
			measured = p.ID
			break
		}
	}
	for i := 0; i < 2; i++ {
		now += 1000
		br.NoteGoodput(lead, 256<<10, 16000, now-16000, now)
		br.NoteGoodput(measured, 256<<10, 16000, now-16000, now)
	}
	probed := br.SweepDue(now)
	if len(probed) != len(paths)-1 || probed[0] != lead {
		t.Fatalf("swept %v, want the leader %s and the %d paths with no goodput", probed, lead, len(paths)-2)
	}
	for _, p := range probed {
		if p == measured {
			t.Fatalf("swept %s, measured already", p)
		}
		br.Swept(p, 256<<10, 16000, true, now+16000)
	}
	if p := br.SweepDue(now + 16000 + DefaultConfig().SweepMs); p != nil {
		t.Fatalf("swept %v again while every path's measure is fresh", p)
	}
}

func (w *sweepRun) paths() []string {
	var out []string
	for p := range w.start {
		out = append(out, p)
	}
	return out
}

// The leader is shaped, but no flow of it reaches BigBytes to measure its
// goodput (a feed of short videos): two flows held back inside the site's
// records make it suspect, and a sweep measures it beside the paths with no
// goodput of their own. One such flow is not enough, nor are flows on a
// leader whose own goodput is fresh and fast.
func TestSweepOfALeaderSuspectOnFlowsHeldBack(t *testing.T) {
	paths := sweepPaths()
	br := New(DefaultConfig(), "t", paths, 7)
	now := warm(br, paths, 1000)
	br.Pick(now, "x", DstTLS443)
	lead := br.Leader()
	now += 3000
	br.NoteSlow(lead, 20<<10, 2000, now-2500, now)
	if p := br.SweepDue(now); p != nil {
		t.Fatalf("swept %v on one flow held back", p)
	}
	now += 3000
	br.NoteSlow(lead, 20<<10, 2000, now-2500, now)
	probed := br.SweepDue(now)
	if len(probed) != len(paths) || probed[0] != lead {
		t.Fatalf("swept %v on two flows held back, want the leader %s and the %d paths with no goodput", probed, lead, len(paths)-1)
	}

	br = New(DefaultConfig(), "t", paths, 7)
	now = warm(br, paths, 1000)
	br.Pick(now, "x", DstTLS443)
	lead = br.Leader()
	for i := 0; i < 2; i++ {
		br.NoteGoodput(lead, 256<<10, 100, now-100, now)
	}
	for i := 0; i < 3; i++ {
		now += 3000
		br.NoteSlow(lead, 20<<10, 2000, now-2500, now)
	}
	if p := br.SweepDue(now); p != nil {
		t.Fatalf("swept %v though the leader's own goodput is fresh and fast", p)
	}
}

// A doubt, or flows held back, on the network the device left say nothing of
// the one it is on, nor of the first when it comes back.
func TestSweepForgetsTheDoubtOfTheNetworkLeft(t *testing.T) {
	paths := sweepPaths()
	br := New(DefaultConfig(), "wifi:a", paths, 7)
	now := warm(br, paths, 1000)
	br.Pick(now, "x", DstTLS443)
	trip(br, br.Leader(), now)
	now += 100
	br.SwitchContext("cell", now)
	if p := br.SweepDue(now + 10); p != nil {
		t.Fatalf("swept %v on cell for the trip of the wifi leader", p)
	}

	br = New(DefaultConfig(), "wifi:a", paths, 7)
	now = warm(br, paths, 1000)
	br.Pick(now, "x", DstTLS443)
	now += 1000
	br.SwitchContext("cell", now)
	br.Pick(now+10, "x", DstTLS443)
	for i := 0; i < 2; i++ {
		now += 3000
		br.NoteSlow(br.Leader(), 20<<10, 2000, now-2500, now)
	}
	now += 1000
	br.SwitchContext("wifi:a", now)
	if p := br.SweepDue(now + 10); p != nil {
		t.Fatalf("swept %v back on wifi for flows held back on cell", p)
	}
}

// The leader's dials hang while the runner-up's connect, flow after flow (an
// allow list, a block of new handshakes): each flow is rescued by the
// connect-stage retry and none files a receipt against the leader, which so
// keeps the lead and costs every flow the stagger. Two races lost in a row put
// it in doubt, though it answered a moment before on a connection already
// open; a race it wins ends the doubt.
func TestSweepOfALeaderThatLosesTheConnectRace(t *testing.T) {
	paths := sweepPaths()
	br := New(DefaultConfig(), "t", paths, 7)
	now := warm(br, paths, 1000)
	br.Pick(now, "x", DstTLS443)
	lead := br.Leader()
	now += 1000
	br.NoteRace(lead, true, now-300, now)
	br.NoteAnswered(lead, now-100, now) // on a connection already open
	if p := br.SweepDue(now); p != nil {
		t.Fatalf("swept %v after one lost race", p)
	}
	now += 500
	br.NoteRace(lead, true, now-300, now)
	probed := br.SweepDue(now)
	if len(probed) != len(paths) || probed[0] != lead {
		t.Fatalf("swept %v after two races lost in a row, want the leader %s and the %d other paths", probed, lead, len(paths)-1)
	}

	br = New(DefaultConfig(), "t", paths, 7)
	now = warm(br, paths, 1000)
	br.Pick(now, "x", DstTLS443)
	lead = br.Leader()
	for _, lost := range []bool{true, false, true} {
		now += 500
		br.NoteRace(lead, lost, now-300, now)
	}
	if p := br.SweepDue(now); p != nil {
		t.Fatalf("swept %v though the leader won the race between its losses", p)
	}
	now += 500
	br.NoteRace(lead, true, now-300, now)
	now += 500
	br.NoteRace(lead, false, now-100, now)
	if p := br.SweepDue(now); p != nil {
		t.Fatalf("swept %v though the leader won a race after its two losses", p)
	}
}

// A leader frozen under the app's open connections answers none of the
// requests sent on them, and nothing else shows it: no flow's record is cut,
// no new flow is dialled. Two flows left unanswered put it in doubt, and the
// sweep takes every available path, measured or not: it may be dead. A
// leader that does not deliver its probe is marked so its flows waiting can
// be closed, until it leads again; one that delivers, however slower, is not.
// One flow left unanswered is not enough, nor flows on another path or ones
// begun before the leader took the lead.
func TestSweepOfALeaderThatLeavesRequestsUnanswered(t *testing.T) {
	paths := sweepPaths()
	setup := func() (*Brain, string, int64) {
		br := New(DefaultConfig(), "t", paths, 7)
		now := warm(br, paths, 1000)
		br.Pick(now, "x", DstTLS443)
		for _, p := range paths {
			br.NoteGoodput(p.ID, 256<<10, 100, now-100, now) // every path measured fast
		}
		return br, br.Leader(), now + 5000
	}
	br, lead, now := setup()
	br.NoteUnanswered(lead, now-3000, now)
	if p := br.SweepDue(now); p != nil {
		t.Fatalf("swept %v on one request unanswered", p)
	}
	for _, p := range paths {
		if p.ID != lead {
			br.NoteUnanswered(p.ID, now-3000, now) // not the leader
			break
		}
	}
	br.NoteUnanswered(lead, br.leaderSince-1, now) // a flow begun before it led
	if p := br.SweepDue(now); p != nil {
		t.Fatalf("swept %v on requests unanswered on another path or begun before the leader led", p)
	}
	now += 500
	br.NoteUnanswered(lead, now-3000, now)
	probed := br.SweepDue(now)
	if len(probed) != len(paths) || probed[0] != lead {
		t.Fatalf("swept %v on two requests unanswered, want the leader %s and the %d other paths", probed, lead, len(paths)-1)
	}
	br.Swept(probed[1], 256<<10, 20, true, now+20)
	br.SweepCheck(now + 1100)
	if br.Leader() == lead {
		t.Fatalf("the leader %s kept the lead without delivering its probe", lead)
	}
	if at := br.ProbeLost(lead); at != now+1100 {
		t.Fatalf("the leader that did not deliver its probe: ProbeLost %d, want %d", at, now+1100)
	}
	br.setLeader(lead, now+2000, "lead_test", "back")
	if at := br.ProbeLost(lead); at != 0 {
		t.Fatalf("a path that leads again: ProbeLost %d, want 0", at)
	}

	br, lead, now = setup()
	br.NoteUnanswered(lead, now-3000, now)
	br.NoteUnanswered(lead, now-3000, now)
	probed = br.SweepDue(now)
	br.Swept(probed[1], 256<<10, 20, true, now+20)
	br.Swept(lead, 256<<10, 3000, true, now+3000)
	if br.Leader() == lead {
		t.Fatalf("the leader %s kept the lead delivering its probe in 3000 ms vs 20", lead)
	}
	if at := br.ProbeLost(lead); at != 0 {
		t.Fatalf("a leader that delivered its probe, slower: ProbeLost %d, want 0", at)
	}
}
