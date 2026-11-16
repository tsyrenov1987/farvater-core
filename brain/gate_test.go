package brain

import "testing"

// Plain vkturn takes flows only in a whitelist zone while CDNvideo answers
// (owner, 16.11.2026); the bond and every other path are never gated.
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

func TestVKGateClosedOnOpenInternet(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	b.st["Orden-ru8"].AnsweredAt = now - 1000
	b.st["de3-reality"].AnsweredAt = now - 2000 // foreign answers: no whitelist zone
	if b.VKOpen(now) {
		t.Fatal("vk open while the open internet answers")
	}
	av := b.available(now)
	if contains(av, "de3-vk") {
		t.Fatalf("plain vk in the fan: %v", av)
	}
	if !contains(av, "de3-kilbond") || !contains(av, "Orden-ru8") || !contains(av, "de3-reality") {
		t.Fatalf("a non-vk path left the fan: %v", av)
	}
	if contains(b.UDPOrder(now), "de3-vk") {
		t.Fatal("plain vk in the UDP order")
	}
}

func TestVKGateOpensInZoneWithCDNvideo(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	b.st["Orden-ru8"].AnsweredAt = now - 1000
	b.Diag.lastWireFail["de3-reality"] = now - 5000
	b.Diag.lastWireFail["de3-xhttp"] = now - 6000
	if !b.VKOpen(now) {
		t.Fatal("vk closed in a whitelist zone with CDNvideo answering")
	}
	if !contains(b.available(now), "de3-vk") {
		t.Fatal("plain vk not in the fan")
	}
	// CDNvideo goes quiet past the window: vk closes, even in the zone.
	later := now + GateWindowMs + 1
	b.Diag.lastWireFail["de3-reality"] = later - 1000
	b.Diag.lastWireFail["de3-xhttp"] = later - 1000
	if b.VKOpen(later) || contains(b.available(later), "de3-vk") {
		t.Fatal("vk open without CDNvideo")
	}
}

func TestVKGateZoneButOnlyOtherWhiteAnswers(t *testing.T) {
	b := gateBrain("cell:25002")
	now := int64(1_000_000)
	b.st["wl2"].AnsweredAt = now - 1000         // YC answers, not CDNvideo
	b.st["de3-kilbond"].AnsweredAt = now - 1000 // the bond is not CDNvideo evidence
	b.Diag.lastWireFail["de3-reality"] = now - 5000
	b.Diag.lastWireFail["de3-xhttp"] = now - 6000
	if b.VKOpen(now) {
		t.Fatal("vk open with no plain CDNvideo path answering")
	}
}

func TestVKGateRestrictedNetwork(t *testing.T) {
	b := gateBrain("cell:25002" + RestrictedSuffix)
	now := int64(1_000_000)
	b.st["Orden-ru8"].AnsweredAt = now - 1000
	if !b.VKOpen(now) {
		t.Fatal("vk closed in a restricted network with CDNvideo answering")
	}
}

func TestVKGateNeverEmptiesTheFan(t *testing.T) {
	b := New(DefaultConfig(), "wifi", []PathInfo{{ID: "only-vk", Rail: "vkturn"}}, 1)
	if av := b.available(1_000_000); len(av) != 1 {
		t.Fatalf("a catalogue of only vk must keep it: %v", av)
	}
}
