package brain

import (
	"encoding/json"
	"fmt"
	"testing"
)

func wirefail(path string, at int64) Receipt {
	return Receipt{Path: path, AtMs: at, WireReadyMs: -1, FirstByteMs: -1, DownAtFail: -1, End: EndTimeout, Dst: "h"}
}

func threePaths(whiteW bool) []PathInfo {
	return []PathInfo{{ID: "A", SNI: "a", IP: "1", Rail: "reality"}, {ID: "B", SNI: "b", IP: "2", Rail: "xhttp"}, {ID: "W", SNI: "w", IP: "3", Rail: "reality", White: whiteW}}
}

// roundTrip passes memory through its file form, as between two sessions.
func roundTrip(t *testing.T, m *Memory) *Memory {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	out := NewMemory()
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatal(err)
	}
	return out
}

// A network met again starts from what was learned there: the path that
// delivered leads at once, instead of the first path of the catalogue. Another
// network does not inherit it.
func TestMemoryLeadsWithWhatDeliveredOnThatNetwork(t *testing.T) {
	now := int64(1_000_000)
	b := New(DefaultConfig(), "cell", threePaths(false), 1)
	b.UseMemory(NewMemory(), nil, now)
	for i := 0; i < 10; i++ {
		b.Observe(deliv("W", now))
		now += 1000
	}
	b.Observe(blackhole("A", now))
	mem := roundTrip(t, b.Remember(now))

	next := New(DefaultConfig(), "cell", threePaths(false), 2)
	next.UseMemory(mem, nil, now+3_600_000)
	if d := next.Pick(now+3_600_000, "h", DstTLS443); next.Leader() != "W" || d.Primary == "A" && !d.Explore {
		t.Fatalf("on the same network the remembered path must lead: leader %q, decision %+v", next.Leader(), d)
	}
	if s := next.State("W"); s.Receipts != 0 || s.Mean() >= 0.9 {
		t.Fatalf("memory must be a weak prior, not evidence: receipts %d, mean %.2f", s.Receipts, s.Mean())
	}
	other := New(DefaultConfig(), "wifi:0a1b2c3d", threePaths(false), 3)
	other.UseMemory(mem, nil, now+3_600_000)
	other.Pick(now+3_600_000, "h", DstTLS443)
	if other.Leader() != "A" {
		t.Fatalf("another network must not inherit the memory: leader %q", other.Leader())
	}
	stale := New(DefaultConfig(), "cell", threePaths(false), 4)
	stale.UseMemory(mem, nil, now+MemoryTTLMs+1)
	stale.Pick(now+MemoryTTLMs+1, "h", DstTLS443)
	if stale.Leader() != "A" {
		t.Fatalf("memory older than the TTL must be forgotten: leader %q", stale.Leader())
	}
}

// Own memory of a network beats the catalogue's advice for it; a path without
// memory still gets the catalogue's prior, also through the network's kind.
func TestMemoryBeatsCataloguePrior(t *testing.T) {
	now := int64(1_000_000)
	mem := NewMemory()
	mem.Ctx["wifi:0a1b2c3d"] = map[string]PathMemory{"B": {A: 0, B: 8, FA: 0, FB: 8, AtMs: now}}
	priors := map[string]map[string]Prior{"wifi": {"B": {A: 20, B: 1}, "W": {A: 20, B: 1}}}
	b := New(DefaultConfig(), "wifi:0a1b2c3d", threePaths(false), 1)
	b.UseMemory(mem, priors, now)
	b.Pick(now, "h", DstTLS443)
	if b.Leader() != "W" {
		t.Fatalf("leader %q: want W, advised by the catalogue for any wifi, B being remembered as failing here", b.Leader())
	}
}

// Moving between networks resumes each one where it was left in the session,
// at once and without a restart.
func TestSwitchContextResumesEachNetwork(t *testing.T) {
	now := int64(1_000_000)
	mem := NewMemory()
	mem.Ctx["cell"] = map[string]PathMemory{"B": {A: 12, B: 0, FA: 12, FB: 0, AtMs: now}}
	b := New(DefaultConfig(), "wifi:0a1b2c3d", threePaths(false), 1)
	b.UseMemory(mem, nil, now)
	for i := 0; i < 5; i++ {
		b.Pick(now, "h", DstTLS443)
		b.Observe(deliv("A", now))
		now += 1000
	}
	if b.Leader() != "A" {
		t.Fatalf("wifi leader %q, want A", b.Leader())
	}
	b.SwitchContext("cell", now)
	b.Pick(now, "h", DstTLS443)
	if b.Ctx() != "cell" || b.Leader() != "B" {
		t.Fatalf("on cell: ctx %q leader %q, want cell/B from memory", b.Ctx(), b.Leader())
	}
	now += 1000
	for i := 0; i < 3; i++ {
		b.Observe(deliv("B", now))
		now += 1000
	}
	b.SwitchContext("wifi:0a1b2c3d", now)
	if b.Leader() != "A" || b.State("A").Receipts != 5 || b.State("B").Receipts != 0 {
		t.Fatalf("back on wifi: leader %q, A receipts %d, B receipts %d; want A, 5, 0", b.Leader(), b.State("A").Receipts, b.State("B").Receipts)
	}
	b.SwitchContext("wifi:0a1b2c3d", now)
	b.SwitchContext("cell", now+1)
	if b.Leader() != "B" || b.State("B").Receipts != 3 {
		t.Fatalf("back on cell: leader %q, B receipts %d; want B, 3", b.Leader(), b.State("B").Receipts)
	}
	if n := b.J.Count("ctx_switch"); n != 3 {
		t.Fatalf("ctx_switch entries %d, want 3 (a switch to the same network is none)", n)
	}
	m := b.Remember(now + 2)
	if m.Ctx["wifi:0a1b2c3d"]["A"].A < 4 || m.Ctx["cell"]["B"].A < 3 {
		t.Fatalf("both networks must be remembered: %+v", m.Ctx)
	}
}

// A flow begun before the network changed says nothing about either network.
func TestFlowAcrossNetworkChangeIsNotEvidence(t *testing.T) {
	b := New(DefaultConfig(), "wifi:0a1b2c3d", threePaths(false), 1)
	b.SwitchContext("cell", 10_000)
	cut := reset("A", 12_000)
	cut.DurMs = 5_000
	b.Observe(cut)
	if b.Dropped != 1 || b.J.Count("drop_netchange") != 1 || b.State("A").Receipts != 0 {
		t.Fatalf("a flow across the change counted: dropped %d, receipts %d", b.Dropped, b.State("A").Receipts)
	}
	fresh := deliv("A", 13_000)
	fresh.DurMs = 2_000
	b.Observe(fresh)
	if b.State("A").Receipts != 1 {
		t.Fatal("a flow begun after the change must count")
	}
}

// A mobile network that lets only allow-listed sites through: the paths go
// silent while such a site answers. The brain moves to the network's
// restricted variant, where the paths that delivered there before (or, the
// first time, the catalogue's allow-listed entries) go first; every path stays
// in the fan; when the silent paths connect again it returns.
func TestRestrictedNetwork(t *testing.T) {
	now := int64(1_000_000)
	b := New(DefaultConfig(), "cell", threePaths(true), 1)
	b.UseMemory(NewMemory(), nil, now)
	b.Pick(now, "h", DstTLS443)
	if b.Leader() != "A" {
		t.Fatalf("an allow-listed path must not be preferred outside a restricted network: leader %q", b.Leader())
	}
	b.Observe(wirefail("A", now))
	b.Observe(wirefail("B", now+1000))
	if !b.Diag.NetDown(now + 1000) {
		t.Fatal("setup: two silent paths should read as the network down")
	}
	b.EnterRestricted(now + 2000)
	b.EnterRestricted(now + 2000)
	if b.Ctx() != "cell:wl" || !b.Restricted() || b.J.Count("restricted_on") != 1 {
		t.Fatalf("ctx %q, restricted_on %d", b.Ctx(), b.J.Count("restricted_on"))
	}
	now += 3000
	b.Pick(now, "h", DstTLS443)
	if b.Leader() != "W" {
		t.Fatalf("restricted, first time: the allow-listed path must lead, got %q", b.Leader())
	}
	picked := map[string]int{}
	for end := now + 11*60_000; now < end; now += 2000 {
		d := b.Pick(now, "h", DstTLS443)
		picked[d.Primary]++
		if d.Primary == "W" {
			b.Observe(deliv("W", now))
		}
	}
	if picked["A"] == 0 || picked["B"] == 0 {
		t.Fatalf("every path must stay in the fan while restricted: picks %v", picked)
	}
	b.Observe(deliv("A", now))
	if !b.Restricted() {
		t.Fatal("one silent path connecting is not yet the end of the restriction")
	}
	b.Observe(deliv("B", now+1000))
	if b.Ctx() != "cell" || b.J.Count("restricted_off") != 1 {
		t.Fatalf("two silent paths connect again: ctx %q, want cell", b.Ctx())
	}
	mem := roundTrip(t, b.Remember(now+2000))
	if mem.Ctx["cell:wl"]["W"].A < 3 {
		t.Fatalf("the restricted network's deliveries must be remembered: %+v", mem.Ctx["cell:wl"])
	}

	// Next session, a catalogue without the allow-list label: memory alone
	// puts W first once the network is restricted again, and only then.
	next := New(DefaultConfig(), "cell", threePaths(false), 2)
	now += 3_600_000
	next.UseMemory(mem, nil, now)
	next.Pick(now, "h", DstTLS443)
	if next.Leader() == "W" {
		t.Fatalf("the restricted network's memory must not lead the plain one")
	}
	next.EnterRestricted(now)
	next.Pick(now, "h", DstTLS443)
	if next.Leader() != "W" {
		t.Fatalf("restricted again: the path that delivered there must lead, got %q", next.Leader())
	}
}

// A restricted network ends with the device leaving the network too; meeting
// the restricted variant again resumes it.
func TestRestrictedEndsWithTheNetwork(t *testing.T) {
	now := int64(1_000_000)
	b := New(DefaultConfig(), "cell", threePaths(true), 1)
	b.Observe(wirefail("A", now))
	b.Observe(wirefail("B", now+1000))
	b.EnterRestricted(now + 2000)
	b.SwitchContext("wifi:0a1b2c3d", now+3000)
	if b.Restricted() || b.Ctx() != "wifi:0a1b2c3d" {
		t.Fatalf("ctx %q after moving to wifi", b.Ctx())
	}
	b.Observe(deliv("A", now+4000))
	b.Observe(deliv("B", now+5000))
	if b.J.Count("restricted_off") != 0 {
		t.Fatal("paths connecting on another network must not end the cell's restriction")
	}
}

func TestMemoryPrune(t *testing.T) {
	now := int64(MemoryTTLMs + 100_000)
	m := NewMemory()
	m.Ctx["old"] = map[string]PathMemory{"A": {A: 3, AtMs: 1}}
	m.Ctx["mixed"] = map[string]PathMemory{"A": {A: 3, AtMs: 1}, "B": {A: 1, AtMs: now}}
	for i := 0; i < MemoryContexts+3; i++ {
		m.Ctx[fmt.Sprintf("wifi:%02d", i)] = map[string]PathMemory{"A": {A: 1, AtMs: now - int64(1000*(i+1))}}
	}
	m.Prune(now)
	if _, ok := m.Ctx["old"]; ok {
		t.Fatal("a network with only stale evidence must be forgotten")
	}
	if _, ok := m.Ctx["mixed"]["A"]; ok || len(m.Ctx["mixed"]) != 1 {
		t.Fatalf("stale paths must go, fresh ones stay: %+v", m.Ctx["mixed"])
	}
	if len(m.Ctx) != MemoryContexts {
		t.Fatalf("%d networks kept, want %d", len(m.Ctx), MemoryContexts)
	}
	for _, gone := range []string{"wifi:16", "wifi:17", "wifi:18"} {
		if _, ok := m.Ctx[gone]; ok {
			t.Fatalf("%s is among the least recent and must be dropped", gone)
		}
	}
}

// When no path connects the brain suspects the local network and counts
// nothing. Once an allow-listed site has answered directly, the network is
// known to be up: the silent paths' failures count, so a dead leader is
// dethroned instead of being dialled for good; the trust lapses unless renewed.
func TestFailuresCountOnceTheNetworkIsKnownUp(t *testing.T) {
	now := int64(1_000_000)
	b := New(DefaultConfig(), "cell", threePaths(false), 1)
	b.Pick(now, "h", DstTLS443)
	b.Observe(wirefail("A", now))
	b.Observe(wirefail("B", now+500))
	if b.Dropped != 1 {
		t.Fatalf("setup: with the network suspect the second failure is dropped, dropped %d", b.Dropped)
	}
	b.EnterRestricted(now + 1000)
	now += 2000
	b.Pick(now, "h", DstTLS443)
	lead := b.Leader()
	b.Observe(wirefail(lead, now))
	b.Observe(wirefail("B", now+200))
	b.Observe(wirefail(lead, now+400))
	if b.Dropped != 1 || b.State(lead).Receipts != 2 {
		t.Fatalf("network known up: failures must count (dropped %d, %s receipts %d)", b.Dropped, lead, b.State(lead).Receipts)
	}
	b.Pick(now+500, "h", DstTLS443)
	if b.Leader() == lead {
		t.Fatalf("a leader that never connects must be dethroned once the network is known up")
	}
	later := now + NetUpTrustMs + 1000
	b.Observe(wirefail("A", later))
	b.Observe(wirefail("B", later+200))
	if b.Dropped != 2 {
		t.Fatalf("the trust must lapse: dropped %d, want 2", b.Dropped)
	}
}
