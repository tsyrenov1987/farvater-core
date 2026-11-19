package brain

import "testing"

// Owner, 18.11.2026: CDNvideo and the bond take flows only on a cellular
// network in a whitelist zone; plain vkturn — in a whitelist zone on any
// network, whether CDNvideo answers or not. Every other path is never gated.
func gateBrain(ctx string) *Brain {
	return New(DefaultConfig(), ctx, []PathInfo{
		{ID: "de3-reality", Rail: "reality", IP: "1.1.1.1"},
		{ID: "de3-xhttp", Rail: "xhttp", IP: "1.1.1.2"},
		{ID: "door-ru1", Rail: "xhttp", IP: "203.0.113.140", White: true, Net: "cell", Door: DoorCDNvideo},
		{ID: "wl2", Rail: "xhttp", IP: "51.250.3.90", White: true, Net: "cell"},
		{ID: "de3-vk", Rail: "vkturn", IP: "2.2.2.2", White: true},
		{ID: "de3-kilbond", Rail: "kilbond", IP: "203.0.113.140", White: true, Net: "cell", Door: DoorCDNvideo},
	}, 1)
}

// openEvidence gives the open internet its proof: quick clean answers over a
// paths meant for it at two entry addresses.
func openEvidence(b *Brain, at int64) {
	b.st["de3-reality"].noteOpen(at - 1)
	b.st["de3-xhttp"].noteOpen(at)
}

// zoneEvidence makes the open paths silent: a whitelist zone by evidence.
func zoneEvidence(b *Brain, now int64) {
	b.Diag.lastWireFail["de3-reality"] = now - 5000
	b.Diag.lastWireFail["de3-xhttp"] = now - 6000
}

// Owner, 18.11.2026: on a cellular network with no whitelists every path is
// in the fan — the zone's end takes none out.
func TestGateOpenInternetCell(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	openEvidence(b, now-2000) // foreign answers quickly: no whitelist zone
	if b.Zone(now) {
		t.Fatal("zone while the open internet answers")
	}
	if !b.VKOpen(now) || !b.CDNOpen(now) {
		t.Fatal("a path gated on a cellular network")
	}
	av := b.available(now)
	for _, p := range b.paths {
		if !contains(av, p.ID) {
			t.Fatalf("%s left the fan on cellular outside the zone: %v", p.ID, av)
		}
	}
	u := b.UDPOrder(now)
	for _, id := range []string{"de3-vk", "door-ru1", "de3-kilbond"} {
		if !contains(u, id) {
			t.Fatalf("%s not in the UDP order: %v", id, u)
		}
	}
}

func TestGateZoneCellOpensAll(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	zoneEvidence(b, now)
	if !b.VKOpen(now) || !b.CDNOpen(now) {
		t.Fatal("gate closed on a cellular network in a whitelist zone")
	}
	av := b.available(now)
	for _, id := range []string{"de3-vk", "door-ru1", "de3-kilbond", "wl2"} {
		if !contains(av, id) {
			t.Fatalf("%s not in the fan in the zone: %v", id, av)
		}
	}
}

// vkturn no longer waits for CDNvideo: it helps when CDNvideo is full or down.
func TestGateVKWithoutCDNvideo(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	zoneEvidence(b, now)
	b.Diag.lastWireFail["door-ru1"] = now - 1000 // CDNvideo fails too
	if !b.VKOpen(now) || !contains(b.available(now), "de3-vk") {
		t.Fatal("vk closed in the zone while CDNvideo is down")
	}
}

// Quick answers over the white, CDNvideo, bond and vk paths prove nothing
// about the open internet.
func TestGateWhiteAnswersAreNoProof(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	for _, id := range []string{"door-ru1", "de3-kilbond", "de3-vk", "wl2"} {
		b.st[id].AnsweredAt = now - 1000
		b.st[id].noteOpen(now - 1000)
		b.st[id].noteOpen(now - 500)
	}
	if !b.Zone(now) || !b.CDNOpen(now) {
		t.Fatal("white paths answering cancelled the zone on cellular")
	}
	w := gateBrain("wifi:ab12")
	for _, id := range []string{"door-ru1", "wl2"} {
		w.st[id].noteOpen(now - 1000)
		w.st[id].noteOpen(now - 500)
	}
	if w.Zone(now) {
		t.Fatal("zone on Wi-Fi without any open path failing")
	}
	zoneEvidence(w, now)
	if !w.Zone(now) {
		t.Fatal("white paths answering must not cancel the zone")
	}
}

// A phone starting on cellular knows nothing yet: CDNvideo, the bond and vk
// are in the fan from the first flow (iOS 68 on МТС, 18.11.2026: they were
// out, and the phone dialled only dead foreign paths, 15 s a try).
func TestGateCellStartKeepsZonePathsIn(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	if !b.Zone(now) || !b.VKOpen(now) || !b.CDNOpen(now) {
		t.Fatal("gate closed at a cellular start with no evidence")
	}
	av := b.available(now)
	for _, id := range []string{"de3-vk", "door-ru1", "de3-kilbond", "de3-reality"} {
		if !contains(av, id) {
			t.Fatalf("%s not in the fan at a cellular start: %v", id, av)
		}
	}
}

// Off cellular nothing changes: the zone takes evidence.
func TestGateWifiStartKeepsVKOut(t *testing.T) {
	b := gateBrain("wifi:ab12")
	now := int64(1_000_000)
	if b.Zone(now) || contains(b.available(now), "de3-vk") {
		t.Fatal("vk open on Wi-Fi with no evidence of a zone")
	}
}

// One answer, or slow answers, over a foreign path is a trickle through the
// lists, not the open internet: the zone holds.
func TestGateTrickleKeepsZone(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	zoneEvidence(b, now)
	for i, ms := range []int64{4000, 6500, 9000} { // answers in 2–9 s, a few KB
		at := now + int64(i)*1000
		b.Observe(Receipt{Path: "de3-xhttp", AtMs: at, WireReadyMs: 900, FirstByteMs: ms, AnswerMs: ms, Down: 3 * KB, DurMs: ms + 2000, End: EndRemoteFin, DownAtFail: -1})
	}
	later := now + 3000
	if b.st["de3-xhttp"].AnsweredAt == 0 {
		t.Fatal("the slow answers were not taken")
	}
	if !b.Zone(later) || !b.CDNOpen(later) {
		t.Fatal("slow foreign answers cancelled the zone")
	}
	b.st["de3-reality"].noteOpen(later) // one quick answer is not proof yet
	if !b.Zone(later) {
		t.Fatal("one quick answer cancelled the zone")
	}
}

// Quick answers through the receipts close the gate.
func TestGateQuickAnswersProveOpen(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	for i, id := range []string{"de3-reality", "de3-xhttp"} { // two entry addresses
		i := int64(i)
		b.Observe(Receipt{Path: id, AtMs: now + i*100, WireReadyMs: 60, FirstByteMs: 300, AnswerMs: 300, Down: 200 * KB, DurMs: 900, End: EndRemoteFin, DownAtFail: -1})
	}
	at := now + 200
	if b.Zone(at) {
		t.Fatal("zone after the open internet answered quickly")
	}
	if !contains(b.available(at), "door-ru1") || !contains(b.available(at), "de3-vk") {
		t.Fatal("a path left the fan on cellular when the zone ended")
	}
}

// A path cut at 16 KB proves nothing.
func TestGateCut16IsNoProof(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	openEvidence(b, now)
	b.st["de3-reality"].Cut16 = true
	if !b.Zone(now) {
		t.Fatal("a path cut at 16 KB cancelled the zone")
	}
}

// The lists coming down on the same network: two open paths failing after
// the proof bring the zone back at once, not when the proof ages out.
func TestGateZoneReturnsAfterProof(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	openEvidence(b, now)
	if b.Zone(now) {
		t.Fatal("zone despite the proof")
	}
	b.Diag.lastWireFail["de3-reality"] = now - 50_000 // before the proof: ignored
	b.Diag.lastWireFail["de3-xhttp"] = now + 5000
	if b.Zone(now + 6000) {
		t.Fatal("one failure after the proof brought the zone back")
	}
	b.Diag.lastWireFail["de3-reality"] = now + 7000
	if !b.Zone(now+8000) || !b.CDNOpen(now+8000) {
		t.Fatal("the zone did not come back after two failures past the proof")
	}
	// An idle phone on the open internet: the proof ages out and the zone is
	// assumed again until the next quick answers.
	c := gateBrain("cell:25002")
	openEvidence(c, now)
	if !c.Zone(now + OpenProofKeepMs + 1000) {
		t.Fatal("the proof held past OpenProofKeepMs")
	}
}

func TestGateWifiZoneKeepsCDNvideoOut(t *testing.T) {
	for _, ctx := range []string{"wifi:ab12", "wired", "wifi:ab12" + RestrictedSuffix} {
		b := gateBrain(ctx)
		now := int64(1_000_000)
		zoneEvidence(b, now)
		if b.CDNOpen(now) {
			t.Fatalf("%s: CDNvideo open off cellular", ctx)
		}
		av := b.available(now)
		if contains(av, "door-ru1") || contains(av, "de3-kilbond") {
			t.Fatalf("%s: CDNvideo or the bond in the fan: %v", ctx, av)
		}
		if !b.VKOpen(now) || !contains(av, "de3-vk") {
			t.Fatalf("%s: vk closed in a whitelist zone: %v", ctx, av)
		}
	}
}

func TestGateRestrictedCell(t *testing.T) {
	b := gateBrain("cell:25002" + RestrictedSuffix)
	now := int64(1_000_000)
	b.st["de3-reality"].AnsweredAt = now - 1000 // the restriction decides, not one answer
	if !b.VKOpen(now) || !b.CDNOpen(now) {
		t.Fatal("gate closed in a restricted cellular network")
	}
}

// The zone's end closes vkturn off cellular, and nothing on cellular.
func TestGateClosesWhenZoneEnds(t *testing.T) {
	for ctx, open := range map[string]bool{"cell:25002": true, "wifi:ab12": false} {
		b := gateBrain(ctx)
		now := int64(1_000_000)
		zoneEvidence(b, now)
		if !b.VKOpen(now) {
			t.Fatalf("%s: zone not seen", ctx)
		}
		later := now + 1000
		openEvidence(b, later) // the open internet is back
		if b.Zone(later) {
			t.Fatalf("%s: zone after the open internet answered", ctx)
		}
		if b.VKOpen(later) != open || contains(b.available(later), "de3-vk") != open || contains(b.available(later), "door-ru1") != open {
			t.Fatalf("%s: vk open %v, fan %v", ctx, b.VKOpen(later), b.available(later))
		}
	}
}

func TestGateNeverEmptiesTheFan(t *testing.T) {
	for _, paths := range [][]PathInfo{
		{{ID: "only-vk", Rail: "vkturn"}},
		{{ID: "only-cdn", Rail: "xhttp", White: true, Net: "cell", Door: DoorCDNvideo}},
	} {
		b := New(DefaultConfig(), "wifi", paths, 1)
		if av := b.available(1_000_000); len(av) != 1 {
			t.Fatalf("a catalogue of only gated paths must keep them: %v", av)
		}
	}
}

// iOS 69 on МТС, 18.11.2026: one CDN front answered twice in two seconds, the
// zone was declared over, vkturn and the bond left the fan with the leader,
// and the front then failed eleven flows. One address proves only itself.
func TestGateOneAddressIsNoProof(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	b.st["de3-reality"].noteOpen(now - 2000)
	b.st["de3-reality"].noteOpen(now - 1000)
	if !b.Zone(now) {
		t.Fatal("two answers at one address ended the zone")
	}
	b.st["de3-xhttp"].noteOpen(now - 500)
	if b.Zone(now) {
		t.Fatal("answers at two addresses did not prove the open internet")
	}
}

// The zone that came back over a proof does not take the next one for
// ZoneRelapseMs: the open paths of such a line answer in bursts.
func TestGateRelapseHoldsZone(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(10_000_000)
	openEvidence(b, now)
	if b.Zone(now + 1000) {
		t.Fatal("no proof taken")
	}
	b.Diag.lastWireFail["de3-reality"] = now + 2000
	b.Diag.lastWireFail["de3-xhttp"] = now + 3000
	if !b.Zone(now + 4000) {
		t.Fatal("the zone did not come back")
	}
	later := now + 5*60_000 // the failures are out of GateWindowMs
	openEvidence(b, later)
	if !b.Zone(later+1000) || !contains(b.available(later+1000), "de3-kilbond") {
		t.Fatal("a second proof inside ZoneRelapseMs ended the zone")
	}
	after := now + 4000 + ZoneRelapseMs + 1000
	openEvidence(b, after)
	if b.Zone(after + 1000) {
		t.Fatal("a fresh proof after ZoneRelapseMs was not taken")
	}
}

// Owner, 18.11.2026: in the zone on cellular CDNvideo and VK work together.
// A leader chosen anew there is the bond, though another path answers now.
func TestGateBondLeadsInEvidentZone(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	zoneEvidence(b, now)
	b.st["door-ru1"].AnsweredAt = now - 100
	b.Pick(now, "example.com:443", 0)
	if b.Leader() != "de3-kilbond" {
		t.Fatalf("leader %s, want the bond", b.Leader())
	}
}

// With the zone only assumed (a cellular start, no evidence) the leader is
// chosen as before: an open network's phone does not start on the bond.
func TestGateBondNotForcedOnAssumedZone(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	b.st["de3-reality"].AnsweredAt = now - 100
	b.Pick(now, "example.com:443", 0)
	if b.Leader() != "de3-reality" {
		t.Fatalf("leader %s, want the path that answers now", b.Leader())
	}
}

// A tripped bond is not chosen, and off cellular the bond is gated anyway.
func TestGateBondLeadNeedsHealthyBond(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	zoneEvidence(b, now)
	for i := 0; i < 8; i++ {
		b.Breaker.NoteSig("de3-kilbond", SigReset, now-10)
	}
	if !b.Breaker.Tripped("de3-kilbond", now) {
		t.Fatal("breaker did not trip the bond")
	}
	b.st["door-ru1"].AnsweredAt = now - 100
	b.Pick(now, "example.com:443", 0)
	if b.Leader() == "de3-kilbond" {
		t.Fatal("a tripped bond took the lead")
	}
}

// A bond that leads and delivers keeps the lead against a longer record.
func TestGateDeliveringBondKeepsLead(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	zoneEvidence(b, now)
	b.Pick(now, "example.com:443", 0)
	if b.Leader() != "de3-kilbond" {
		t.Fatalf("leader %s", b.Leader())
	}
	for i := 0; i < 30; i++ {
		b.st["door-ru1"].evDelivA++
		b.st["door-ru1"].evFbA++
		b.st["door-ru1"].recent = append(b.st["door-ru1"].recent, now)
	}
	later := now + b.cfg.MinLeadMs + 1000
	zoneEvidence(b, later)
	b.st["door-ru1"].recent = nil
	for i := 0; i < 30; i++ {
		b.st["door-ru1"].recent = append(b.st["door-ru1"].recent, later-1000)
	}
	b.st["de3-kilbond"].AnsweredAt = later - 500
	b.Pick(later, "example.com:443", 0)
	if b.Leader() != "de3-kilbond" {
		t.Fatalf("the delivering bond lost the lead to %s", b.Leader())
	}
}

// Owner, 19.11.2026: the Yandex CDN entry (#door=ycdn) takes flows only in a
// whitelist zone, on every network; its answers are no proof of the open
// internet.
func ycdnBrain(ctx string) *Brain {
	b := gateBrain(ctx)
	p := PathInfo{ID: "advin-ycdn", Rail: "kilvater", IP: "188.72.112.1", Door: DoorYandexCDN}
	return New(DefaultConfig(), ctx, append(append([]PathInfo{}, b.paths...), p), 1)
}

func TestGateYandexCDNOnlyInZone(t *testing.T) {
	now := int64(1_000_000)
	for _, ctx := range []string{"cell:25002", "wifi:ab12"} {
		b := ycdnBrain(ctx)
		openEvidence(b, now-2000)
		if b.Zone(now) || contains(b.available(now), "advin-ycdn") {
			t.Fatalf("%s: Yandex CDN in the fan on the open internet", ctx)
		}
		if ctx == "cell:25002" && !contains(b.available(now), "door-ru1") {
			t.Fatal("the ycdn gate took CDNvideo off cellular")
		}
		z := ycdnBrain(ctx)
		zoneEvidence(z, now)
		if !z.Zone(now) || !contains(z.available(now), "advin-ycdn") {
			t.Fatalf("%s: Yandex CDN out of the fan in a whitelist zone", ctx)
		}
	}
	// A cellular start assumes the zone: in from the first flow.
	if s := ycdnBrain("cell:25002"); !contains(s.available(now), "advin-ycdn") {
		t.Fatal("Yandex CDN out at a cellular start")
	}
	// Wi-Fi with no evidence is no zone.
	if w := ycdnBrain("wifi:ab12"); contains(w.available(now), "advin-ycdn") {
		t.Fatal("Yandex CDN in on Wi-Fi with no zone")
	}
}

func TestGateYandexCDNAnswersAreNoProof(t *testing.T) {
	now := int64(1_000_000)
	b := ycdnBrain("cell:25002")
	b.st["advin-ycdn"].noteOpen(now - 1000)
	b.st["advin-ycdn"].noteOpen(now - 500)
	b.st["de3-reality"].noteOpen(now - 400)
	if !b.Zone(now) {
		t.Fatal("Yandex CDN answers cancelled the zone")
	}
}

// On cellular with no Yandex CDN entry nothing is gated, and picking the fan
// does not ask the zone: its relapse mark stays as it was.
func TestGateCellNoYandexCDNSkipsZone(t *testing.T) {
	now := int64(1_000_000)
	b := gateBrain("cell:25002")
	openEvidence(b, now-20_000)
	zoneEvidence(b, now)
	if g := b.gated(now); g != nil {
		t.Fatalf("gated on cellular without ycdn: %v", g)
	}
	if b.relapseAt != 0 {
		t.Fatalf("relapseAt = %d, want 0: the zone was asked", b.relapseAt)
	}
	y := ycdnBrain("cell:25002")
	openEvidence(y, now-20_000)
	zoneEvidence(y, now)
	if y.gated(now)["advin-ycdn"] == y.Zone(now) {
		t.Fatalf("ycdn gate disagrees with Zone")
	}
}
