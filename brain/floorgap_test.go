package brain

import (
	"fmt"
	"testing"
)

// 14.11.2026: the CDN entry carries ~40 paths on one address. Seeded together,
// they came due for the floor together, and a page's burst of flows sent one
// fresh handshake to each of them within half a second. The floor's flows to
// one address are spaced FloorGapMs apart, and every path still gets one.
func TestFloorSpacesFlowsToOneAddress(t *testing.T) {
	var paths []PathInfo
	for i := range 40 {
		paths = append(paths, PathInfo{ID: fmt.Sprintf("x%d", i), SNI: fmt.Sprintf("x%d.cdn", i), IP: "78.159.245.140", Rail: "xhttp"})
	}
	paths = append(paths, PathInfo{ID: "N", SNI: "n", IP: "5.5.5.5", Rail: "reality"})
	cfg := DefaultConfig()
	b := New(cfg, "t", paths, 1)
	now := int64(1000)
	b.Pick(now, "h", DstTLS443) // seeds every path's floor clock
	now += cfg.FloorMs
	var last int64 = -1
	got := map[string]bool{}
	for range 4000 { // a flow every 100 ms for 400 s
		now += 100
		d := b.Pick(now, "h", DstTLS443)
		if d.Reason != "explore_floor" {
			continue
		}
		if b.info(d.Primary).IP != "78.159.245.140" {
			continue
		}
		if last >= 0 && now-last < 2000 { // a literal: FloorGapMs set to 0 must fail here
			t.Fatalf("floor flows to one address %d ms apart", now-last)
		}
		last = now
		got[d.Primary] = true
	}
	seeded := now - 4000*100
	for _, p := range paths {
		if b.lastPick[p.ID] <= seeded {
			t.Fatalf("path %s got no flow in 400 s past its floor (floor gave %d)", p.ID, len(got))
		}
	}
}
