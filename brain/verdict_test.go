package brain

import "testing"

// One probe is no verdict; two in a row are. The verdict is the zone's
// evidence and the open internet's proof on a cellular network.
func TestVerdictNeedsTwoProbes(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	b.NoteZoneProbe(true, 0, now)
	if v := b.Verdict(now); v != VerdictUnknown {
		t.Fatalf("verdict %s after one probe", v)
	}
	b.NoteZoneProbe(true, 0, now+10_000)
	if v := b.Verdict(now + 10_000); v != VerdictZone {
		t.Fatalf("verdict %s after two probes with no foreign answer", v)
	}
	if ev, _ := b.zoneEvident(now + 10_000); !ev {
		t.Fatal("a zone verdict is the zone's evidence")
	}
	// One probe that got through does not end the zone; the second does.
	b.NoteZoneProbe(true, 3, now+20_000)
	if v := b.Verdict(now + 20_000); v != VerdictZone {
		t.Fatalf("verdict %s after one open probe", v)
	}
	b.NoteZoneProbe(true, 3, now+30_000)
	if v := b.Verdict(now + 30_000); v != VerdictOpen || b.Zone(now+30_000) {
		t.Fatalf("verdict %s, zone %v after two open probes", v, b.Zone(now+30_000))
	}
}

// The paths' own failures do not make a zone of a network that answered
// directly: an address blocked, a node loaded, a poor radio fail them too.
func TestVerdictOpenOutweighsPathFailures(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	b.NoteZoneProbe(true, 4, now)
	b.NoteZoneProbe(true, 4, now+10_000)
	zoneEvidence(b, now+20_000)
	if b.Zone(now+20_000) || b.bondLead(b.available(now+20_000), now+20_000) != "" {
		t.Fatal("open paths failing made a zone over the network's own answer")
	}
	if !b.ZoneProbeDue(now+10_000+ProbeDoubtMs, now+10_000) {
		t.Fatal("the paths disagree with the verdict: the network is asked again sooner")
	}
	if b.ZoneProbeDue(now+10_000+ProbeDoubtMs-1, now+10_000) {
		t.Fatal("asked again too soon")
	}
}

// No allow-listed answer is no network; one foreign answer may be an
// operator's listed site: neither says anything, and an unclear probe breaks
// the run of agreeing ones.
func TestVerdictUnclearProbes(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	b.NoteZoneProbe(false, 0, now)
	b.NoteZoneProbe(false, 0, now+10_000)
	if v := b.Verdict(now + 10_000); v != VerdictUnknown {
		t.Fatalf("verdict %s with no network", v)
	}
	b.NoteZoneProbe(true, 0, now+20_000)
	b.NoteZoneProbe(true, 1, now+30_000)
	b.NoteZoneProbe(true, 0, now+40_000)
	if v := b.Verdict(now + 40_000); v != VerdictUnknown {
		t.Fatalf("verdict %s: an unclear probe must break the run", v)
	}
	if !b.Zone(now + 40_000) {
		t.Fatal("no verdict on cellular: the zone stays assumed")
	}
}

// Whitelists are a mobile thing: Wi-Fi is not asked and takes no verdict; a
// verdict does not outlive the network or VerdictKeepMs.
func TestVerdictCellOnlyAndExpires(t *testing.T) {
	w := gateBrain("wifi:aa")
	now := int64(1_000_000)
	if w.ZoneProbeDue(now, 0) {
		t.Fatal("wifi asked")
	}
	w.NoteZoneProbe(true, 0, now)
	w.NoteZoneProbe(true, 0, now+1)
	if w.Verdict(now+1) != VerdictUnknown {
		t.Fatal("wifi took a verdict")
	}
	b := gateBrain("cell:25002")
	if !b.ZoneProbeDue(now, 0) {
		t.Fatal("a cellular network with no verdict is asked at once")
	}
	b.NoteZoneProbe(true, 5, now)
	b.NoteZoneProbe(true, 5, now+10_000)
	if b.ZoneProbeDue(now+10_000+ProbeOpenMs-1, now+10_000) || !b.ZoneProbeDue(now+10_000+ProbeOpenMs, now+10_000) {
		t.Fatal("an open network is asked every ProbeOpenMs")
	}
	if b.Verdict(now+10_000+VerdictKeepMs+1) != VerdictUnknown {
		t.Fatal("verdict outlived VerdictKeepMs")
	}
	b.SwitchContext("cell:25001", now+20_000)
	if b.Verdict(now+20_000) != VerdictUnknown {
		t.Fatal("verdict outlived the network")
	}
}

// On the open mobile internet every path stays in the fan, but the paid door,
// the bond and vkturn do not lead while an open path can; in a zone the bond
// leads.
func TestVerdictOpenPutsPaidDoorBehind(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	b.NoteZoneProbe(true, 4, now)
	b.NoteZoneProbe(true, 4, now+10_000)
	now += 20_000
	avail := b.available(now)
	if len(avail) != 6 {
		t.Fatalf("fan %v: every path stays in it", avail)
	}
	for _, p := range b.front(avail, now) {
		if i := b.info(p); vkGated(i) || cdnGated(i) {
			t.Fatalf("%s may lead anew on the open internet", p)
		}
	}
	for i := 0; i < 30; i++ {
		b.Pick(now+int64(i), "example.com:443", 0)
	}
	if i := b.info(b.Leader()); vkGated(i) || cdnGated(i) {
		t.Fatalf("leader %s on the open mobile internet", b.Leader())
	}

	z := gateBrain("cell:25002")
	z.NoteZoneProbe(true, 0, now)
	z.NoteZoneProbe(true, 0, now+10_000)
	if l := z.bondLead(z.available(now+10_000), now+10_000); l != "de3-kilbond" {
		t.Fatalf("bond lead %q in a zone the network confirmed", l)
	}
	if len(z.front(z.available(now+10_000), now+10_000)) != 6 {
		t.Fatal("in a zone nothing rides behind")
	}
}

// A phone starts on cellular assuming a zone, and the paid door may lead by
// then: the open internet's proof hands the lead to an open path.
func TestVerdictOpenTakesLeadFromPaidDoor(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	b.setLeader("door-ru1", now, "test", "")
	b.NoteZoneProbe(true, 2, now+1000)
	if b.Leader() != "door-ru1" {
		t.Fatal("one probe moved the lead")
	}
	b.NoteZoneProbe(true, 2, now+11_000)
	if i := b.info(b.Leader()); vkGated(i) || cdnGated(i) {
		t.Fatalf("leader %s after the open internet proved itself", b.Leader())
	}
	// With every open path tripped the paid door keeps the lead.
	c := gateBrain("cell:25002")
	c.setLeader("door-ru1", now, "test", "")
	for _, p := range []string{"de3-reality", "de3-xhttp", "wl2"} {
		c.Breaker.rail(p).trippedUntil = now + 600_000
	}
	c.NoteZoneProbe(true, 2, now+1000)
	c.NoteZoneProbe(true, 2, now+11_000)
	if c.Leader() != "door-ru1" {
		t.Fatalf("leader %s: nothing else was free", c.Leader())
	}
}
