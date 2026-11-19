package brain

import (
	"fmt"
	"testing"
)

// benchBrain is a catalogue the size of a live one (285 paths, 19.11.2026),
// every open path with a record of answers, so the zone's checks walk it all.
func benchBrain(ctx string, ycdn bool) *Brain {
	var ps []PathInfo
	for i := 0; i < 285; i++ {
		ps = append(ps, PathInfo{ID: fmt.Sprintf("p%d", i), Rail: "reality", IP: fmt.Sprintf("10.0.%d.%d", i/250, i%250)})
	}
	if ycdn {
		ps = append(ps, PathInfo{ID: "ycdn", Rail: "kilvater", IP: "192.0.2.1", Door: DoorYandexCDN})
	}
	b := New(DefaultConfig(), ctx, ps, 1)
	for _, p := range ps {
		for k := 0; k < openKeep; k++ {
			b.st[p.ID].noteOpen(int64(900_000 + k))
		}
	}
	return b
}

func BenchmarkAvailable(b *testing.B) {
	for _, c := range []struct {
		ctx  string
		ycdn bool
	}{{"cell:25002", false}, {"cell:25002", true}, {"wifi:ab12", false}, {"wifi:ab12", true}} {
		b.Run(fmt.Sprintf("%s/ycdn=%v", c.ctx, c.ycdn), func(b *testing.B) {
			br := benchBrain(c.ctx, c.ycdn)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				br.available(1_000_000)
			}
		})
	}
}
