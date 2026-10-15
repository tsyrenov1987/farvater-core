package switchboard

import (
	"testing"

	"github.com/tsyrenov1987/farvater-core/brain"
	"github.com/tsyrenov1987/farvater-core/wire"
)

// A path that takes an upload and never lets an answer through (the TSPU
// dropping a frozen flow's packets) shows no stall: nothing comes down at all.
// The app gives up and closes. A flow closed after waiting that long for an
// answer to what it sent is a stall the app abandoned, not a delivery; the
// small control frames a connection sends while idle and the close_notify at
// its end are not a request.
func TestUnansweredUploadIsAbandoned(t *testing.T) {
	run := func(up []int, wait int64) brain.Receipt {
		f := &flow{s: &Switchboard{cfg: DefaultConfig()}}
		a := f.newAttempt("p", false)
		a.startMs = nowMs() - 30_000
		a.readyMs = a.startMs + 100
		a.m.Down(make([]byte, 64<<10)) // an earlier answer, 64 KB
		for _, n := range up {
			a.m.Up(make([]byte, n))
		}
		a.m.askedAt -= wait
		return a.runReceipt(f, 0, wire.OutcomeClientFin, nil, false)
	}
	if r := run([]int{16 << 10, 16 << 10, 24}, 20_000); r.End != brain.EndStallAbandon || r.Delivered() || r.Sig() != brain.SigThrottle {
		t.Fatalf("32 KB sent, 20 s unanswered, closed by the app: end %v, delivered %v, sig %v; want stall_abandon, not delivered, throttle",
			r.End, r.Delivered(), r.Sig())
	}
	if r := run([]int{16 << 10}, 3_000); r.End != brain.EndLocalClose {
		t.Fatalf("closed 3 s after a request: end %v, want local_close (the app may just leave)", r.End)
	}
	if r := run([]int{13 + 22, 24}, 120_000); r.End != brain.EndLocalClose || !r.Delivered() {
		t.Fatalf("an idle connection's control frame and close_notify: end %v, delivered %v; want local_close, delivered", r.End, r.Delivered())
	}
}
