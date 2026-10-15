package switchboard

import (
	"testing"

	"github.com/tsyrenov1987/farvater-core/wire"
)

// The answer time runs from the dial, not from the flow's start: the wait for
// a handshake slot is the device's own load, not the path's round trips. A
// flow whose app had sent nothing with the dial has none.
func TestAnswerTimeLeavesPacingOut(t *testing.T) {
	f := &flow{s: &Switchboard{cfg: DefaultConfig()}}
	a := f.newAttempt("p", false)
	a.startMs = 1000
	a.dialAt = 1900 // 900 ms waiting for the governor
	a.m.firstDownAt = 2050
	if r := a.runReceipt(f, 300, wire.OutcomeRemoteFin, nil, false); r.AnswerMs != 150 || r.FirstByteMs != 1050 {
		t.Fatalf("answer %d ms, first byte %d ms; want 150 and 1050", r.AnswerMs, r.FirstByteMs)
	}
	if r := a.runReceipt(f, 0, wire.OutcomeRemoteFin, nil, false); r.AnswerMs != 0 {
		t.Fatalf("answer %d ms for a flow with no request at the dial, want 0 (unknown)", r.AnswerMs)
	}
}
