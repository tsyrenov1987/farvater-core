package brain

import "testing"

// Owner, 18.11.2026: CDNvideo and the bond take flows only on a cellular
// network in a whitelist zone; plain vkturn — in a whitelist zone on any
// network, whether CDNvideo answers or not. Every other path is never gated.
func gateBrain(ctx string) *Brain {
	return New(DefaultConfig(), ctx, []PathInfo{
		{ID: "de3-reality", Rail: "reality", IP: "1.1.1.1"},
		{ID: "de3-xhttp", Rail: "xhttp", IP: "1.1.1.2"},
		{ID: "Orden-ru8", Rail: "xhttp", IP: "78.159.245.140", White: true, Net: "cell", Door: DoorCDNvideo},
		{ID: "wl2", Rail: "xhttp", IP: "51.250.3.90", White: true, Net: "cell"},
		{ID: "de3-vk", Rail: "vkturn", IP: "2.2.2.2", White: true},
		{ID: "de3-kilbond", Rail: "kilbond", IP: "78.159.245.140", White: true, Net: "cell", Door: DoorCDNvideo},
	}, 1)
}

// zoneEvidence makes the open paths silent: a whitelist zone by evidence.
func zoneEvidence(b *Brain, now int64) {
	b.Diag.lastWireFail["de3-reality"] = now - 5000
	b.Diag.lastWireFail["de3-xhttp"] = now - 6000
}

func TestGateOpenInternetCell(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	b.st["Orden-ru8"].AnsweredAt = now - 1000
	b.st["de3-reality"].AnsweredAt = now - 2000 // foreign answers: no whitelist zone
	if b.Zone(now) || b.VKOpen(now) || b.CDNOpen(now) {
		t.Fatal("gate open while the open internet answers")
	}
	av := b.available(now)
	for _, id := range []string{"de3-vk", "Orden-ru8", "de3-kilbond"} {
		if contains(av, id) {
			t.Fatalf("%s in the fan outside the zone: %v", id, av)
		}
	}
	if !contains(av, "de3-reality") || !contains(av, "de3-xhttp") || !contains(av, "wl2") {
		t.Fatalf("an ungated path left the fan: %v", av)
	}
	u := b.UDPOrder(now)
	if contains(u, "de3-vk") || contains(u, "Orden-ru8") || contains(u, "de3-kilbond") {
		t.Fatalf("a gated path in the UDP order: %v", u)
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
	for _, id := range []string{"de3-vk", "Orden-ru8", "de3-kilbond", "wl2"} {
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
	b.Diag.lastWireFail["Orden-ru8"] = now - 1000 // CDNvideo fails too
	if !b.VKOpen(now) || !contains(b.available(now), "de3-vk") {
		t.Fatal("vk closed in the zone while CDNvideo is down")
	}
}

// CDNvideo evidence does not make a zone: its own answers are left out.
func TestGateCDNvideoAnswerIsNotZoneEvidence(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	b.st["Orden-ru8"].AnsweredAt = now - 1000
	b.st["de3-kilbond"].AnsweredAt = now - 1000
	b.st["de3-vk"].AnsweredAt = now - 1000
	b.st["wl2"].AnsweredAt = now - 1000
	if b.Zone(now) {
		t.Fatal("zone without any open path failing")
	}
	zoneEvidence(b, now)
	if !b.Zone(now) {
		t.Fatal("white paths answering must not cancel the zone")
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
		if contains(av, "Orden-ru8") || contains(av, "de3-kilbond") {
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

func TestGateClosesWhenZoneEnds(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	zoneEvidence(b, now)
	if !b.CDNOpen(now) {
		t.Fatal("zone not seen")
	}
	later := now + 1000
	b.st["de3-reality"].AnsweredAt = later // the open internet is back
	if b.CDNOpen(later) || b.VKOpen(later) || contains(b.available(later), "Orden-ru8") {
		t.Fatal("gate stays open after the open internet answered")
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
