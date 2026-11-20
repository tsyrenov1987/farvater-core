package brain

import (
	"fmt"
	"testing"
)

// liveBrain is a catalogue shaped like a live one (20.11.2026): n paths over
// a few dozen entry addresses, several rails, some white, a CDN door, a bond.
func liveBrain(ctx string, n int) *Brain {
	rails := []string{"reality", "xhttp", "kilvater", "hy2", "vkturn"}
	var ps []PathInfo
	for i := 0; i < n; i++ {
		p := PathInfo{ID: fmt.Sprintf("p%d", i), Rail: rails[i%len(rails)], SNI: fmt.Sprintf("s%d.example", i%40),
			IP: fmt.Sprintf("192.0.2.%d", i%48), Group: fmt.Sprintf("g%d", i%6), White: i%7 == 0}
		if i%11 == 0 {
			p.Door = DoorCDNvideo
		}
		if i%29 == 0 {
			p.Rail = "kilbond"
		}
		p.NotHTTP = p.Rail == "hy2"
		ps = append(ps, p)
	}
	ps = append(ps, PathInfo{ID: "ycdn", Rail: "kilvater", IP: "198.51.100.1", Door: DoorYandexCDN})
	return New(DefaultConfig(), ctx, ps, 1)
}

// BenchmarkPick is a page's worth of flows on a warm brain: each flow is
// picked and its receipt observed.
func BenchmarkPick(b *testing.B) {
	for _, n := range []int{60, 170, 348} {
		for _, ctx := range []string{"cell:25001", "wifi:ab12"} {
			b.Run(fmt.Sprintf("%s/n=%d", ctx, n), func(b *testing.B) {
				br := liveBrain(ctx, n)
				now := int64(1_000_000)
				for i := 0; i < 2000; i++ { // warm: every path has a record
					now += 50
					d := br.Pick(now, "h.example:443", DstOther)
					br.Observe(Receipt{Path: d.Primary, AtMs: now + 40, DurMs: 40, WireReadyMs: 10, FirstByteMs: 30, AnswerMs: 30, Down: 40_000, End: EndRemoteFin, Dst: "h.example:443"})
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					now += 50
					d := br.Pick(now, "h.example:443", DstOther)
					br.Observe(Receipt{Path: d.Primary, AtMs: now + 40, DurMs: 40, WireReadyMs: 10, FirstByteMs: 30, AnswerMs: 30, Down: 40_000, End: EndRemoteFin, Dst: "h.example:443"})
				}
			})
		}
	}
}
