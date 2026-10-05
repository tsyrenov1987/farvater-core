package switchboard

import (
	"testing"

	"github.com/tsyrenov1987/farvater-core/brain"
)

// The apps colour and word each receipt by the breaker's own signature.
func TestViewCarriesTheSignature(t *testing.T) {
	r := brain.Receipt{WireReadyMs: 20, FirstByteMs: 30, Down: 10 * brain.KB, DownAtFail: 10 * brain.KB, End: brain.EndWireReset}
	if got := view(r).Sig; got != "reset" {
		t.Fatalf("reset receipt: sig=%q", got)
	}
	r.End, r.DownAtFail = brain.EndRemoteFin, -1
	if got := view(r).Sig; got != "" {
		t.Fatalf("served receipt: sig=%q, want empty", got)
	}
}
