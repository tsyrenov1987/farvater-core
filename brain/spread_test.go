package brain

import "testing"

func spreadPaths() []PathInfo {
	return []PathInfo{
		{ID: "A", SNI: "a", IP: "1", Group: "ams"}, {ID: "B", SNI: "b", IP: "2", Group: "ams"}, {ID: "C", SNI: "c", IP: "3", Group: "ams"},
		{ID: "D", SNI: "d", IP: "4", Group: "ams"}, {ID: "E", SNI: "e", IP: "5", Group: "fra"}, {ID: "F", SNI: "f", IP: "6"},
	}
}

// drive picks n flows 200 ms apart from at, answers each as answer says
// (nil: served), and counts the picks by path and by reason.
func drive(b *Brain, at int64, n int, answer func(path string, at int64) Receipt) (byPath, spreadTo map[string]int, end int64) {
	byPath, spreadTo = map[string]int{}, map[string]int{}
	for i := 0; i < n; i++ {
		now := at + int64(i)*200
		d := b.Pick(now, "h", DstTLS443)
		byPath[d.Primary]++
		if d.Reason == "spread" || d.Reason == "spread_trial" {
			spreadTo[d.Primary]++
		}
		r := served(d.Primary, now+100)
		if answer != nil {
			r = answer(d.Primary, now+100)
		}
		b.Observe(r)
		end = now + 200
	}
	return
}

// Off, as it is by default, the leader takes every flow that is not
// exploration, whatever groups the catalogue names.
func TestSpreadOffLeavesFlowsToTheLeader(t *testing.T) {
	b := New(DefaultConfig(), "t", spreadPaths(), 1)
	byPath, spreadTo, _ := drive(b, 1000, 600, nil)
	if len(spreadTo) != 0 {
		t.Fatalf("spread is off, yet flows were shared out: %v", spreadTo)
	}
	if l := b.Leader(); byPath[l] < 500 {
		t.Fatalf("leader %s took %d of 600 flows, want about nine in ten: %v", l, byPath[l], byPath)
	}
}

// With Spread 3 the leader and its two best mates of the same group take
// turns; the group's fourth path, the other group's and the ungrouped one get
// only what exploration gives them, and no path leaves the fan.
func TestSpreadSharesFlowsWithinTheLeadersGroup(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Spread = 3
	b := New(cfg, "t", spreadPaths(), 1)
	_, _, at := drive(b, 1000, 600, nil) // every path earns its receipts by exploration
	byPath, spreadTo, _ := drive(b, at, 900, nil)
	l := b.Leader()
	if b.info(l).Group != "ams" {
		t.Fatalf("leader %s is not of the group under test", l)
	}
	if len(spreadTo) != 2 {
		t.Fatalf("flows were shared with %v, want two mates", spreadTo)
	}
	for p, n := range spreadTo {
		if p == l || b.info(p).Group != "ams" {
			t.Fatalf("flows were shared with %s, not a mate of %s: %v", p, l, spreadTo)
		}
		if n < 200 || byPath[l] < 200 {
			t.Fatalf("turns are uneven: leader %d, shared %v of 900", byPath[l], spreadTo)
		}
	}
	if byPath[l] > 400 {
		t.Fatalf("leader %s still took %d of 900 flows: %v", l, byPath[l], byPath)
	}
	for _, p := range spreadPaths() {
		if byPath[p.ID] == 0 {
			t.Fatalf("path %s got no flow at all: %v", p.ID, byPath)
		}
	}
}

// A mate the breaker takes off stops sharing at once; the leader and the
// other mate carry on, and the tripped path is still in the fan afterwards.
func TestSpreadDropsAMateThatStopsDelivering(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Spread = 3
	b := New(cfg, "t", spreadPaths(), 1)
	_, _, at := drive(b, 1000, 600, nil)
	_, spreadTo, at := drive(b, at, 300, nil)
	victim := ""
	for p := range spreadTo {
		victim = p
		break
	}
	if victim == "" {
		t.Fatal("no mate to break")
	}
	trippedAt := int64(0)
	_, _, at = drive(b, at, 300, func(path string, now int64) Receipt {
		if path != victim {
			return served(path, now)
		}
		if trippedAt == 0 && b.Breaker.Tripped(victim, now) {
			trippedAt = now
		}
		return reset(path, now)
	})
	if trippedAt == 0 && !b.Breaker.Tripped(victim, at) {
		t.Fatalf("the breaker never took %s off", victim)
	}
	_, spreadTo, at = drive(b, at, 100, nil)
	if b.Breaker.Tripped(victim, at) && spreadTo[victim] != 0 {
		t.Fatalf("%d flows were shared with tripped %s", spreadTo[victim], victim)
	}
	if !contains(b.available(at+24*3600_000), victim) {
		t.Fatalf("%s left the fan for good", victim)
	}
}

// A leader that has stopped answering keeps its flows to itself: they are
// what proves it or dethrones it.
func TestSpreadWaitsForALeaderThatAnswers(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Spread = 3
	b := New(cfg, "t", spreadPaths(), 1)
	_, _, at := drive(b, 1000, 900, nil)
	at += 2 * LeadFreshMs // silence: nothing answered lately
	if p, _ := b.spread(b.available(at), at); p != "" {
		t.Fatalf("a flow was shared with %s while the leader had not answered for %d ms", p, 2*LeadFreshMs)
	}
}

// A leader that delivers well leaves exploration little: its mates are found
// by trial, one flow at a time, and share its flows within the first minute.
func TestSpreadRecruitsMatesByTrial(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Spread = 3
	b := New(cfg, "t", spreadPaths(), 1)
	_, _, at := drive(b, 1000, 100, nil) // 20 s
	if m := b.mates(b.available(at), at); len(m) != 2 {
		t.Fatalf("after 100 flows the leader %s has mates %v, want two", b.Leader(), m)
	}
	byPath, _, _ := drive(b, at, 300, nil)
	if l := b.Leader(); byPath[l] > 150 {
		t.Fatalf("leader %s still took %d of 300 flows: %v", l, byPath[l], byPath)
	}
}

// A path whose flow on trial fails is tried no more: it cost one flow, which
// the backup dial covers, and it stays in the fan for exploration to judge.
func TestSpreadEndsATrialAtTheFirstFailure(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Spread = 4 // every path of the group is wanted as a mate
	b := New(cfg, "t", spreadPaths(), 1)
	trials := map[string]int{}
	at := int64(1000)
	for i := 0; i < 300; i++ {
		now := at + int64(i)*200
		d := b.Pick(now, "h", DstTLS443)
		if d.Reason == "spread_trial" {
			trials[d.Primary]++
		}
		if d.Primary == "C" {
			b.Observe(blackhole("C", now+100))
		} else {
			b.Observe(served(d.Primary, now+100))
		}
	}
	if b.Leader() == "C" {
		t.Skip("C leads: nothing to try it for")
	}
	if trials["C"] != 1 {
		t.Fatalf("C fails every flow and got %d flows on trial, want the one: %v", trials["C"], trials)
	}
	if !contains(b.available(at+24*3600_000), "C") {
		t.Fatal("C left the fan for good")
	}
}

// Spread on, as the apps ship it, but a catalogue with no #group labels (every
// catalogue the server sends while fv_spread_on is unset): every decision is
// the one Spread 0 makes, flow for flow, through failures as well.
func TestSpreadWithoutGroupsChangesNothing(t *testing.T) {
	paths := spreadPaths()
	for i := range paths {
		paths[i].Group = ""
	}
	on := DefaultConfig()
	on.Spread = 3
	a, b := New(DefaultConfig(), "t", paths, 1), New(on, "t", paths, 1)
	for i := 0; i < 2000; i++ {
		now := 1000 + int64(i)*200
		da, db := a.Pick(now, "h", DstTLS443), b.Pick(now, "h", DstTLS443)
		if da != db {
			t.Fatalf("flow %d: off %+v, on %+v", i, da, db)
		}
		r := served(da.Primary, now+100)
		if (i/150)%3 == 1 && da.Primary == a.Leader() {
			r = dialTimeout(da.Primary, now+100)
		}
		a.Observe(r)
		b.Observe(r)
	}
}
