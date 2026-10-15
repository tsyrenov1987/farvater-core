package wire

import (
	"context"
	"errors"
	"io"
	"syscall"
	"testing"
)

// settle's callers pass the cancel of the very context it checks. A reset the
// path deals mid-flow was read after that cancel and so passed for a flow the
// caller canceled: the switchboard filed it as the app closing the flow, and a
// path cutting every download after some tens of KB counted as delivering.
func TestSettleTellsAPathResetFromACancel(t *testing.T) {
	run := func(downE error, cancelFirst bool) (Outcome, error) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if cancelFirst {
			cancel()
		}
		up, down := make(chan error, 1), make(chan error, 1)
		down <- downE
		return settle(ctx, up, down, cancel, nil)
	}
	if o, err := run(syscall.ECONNRESET, false); o != OutcomeError || !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("path reset mid-flow: %v %v, want OutcomeError", o, err)
	}
	if o, _ := run(errors.New("use of closed network connection"), true); o != OutcomeCanceled {
		t.Fatalf("caller canceled: %v, want OutcomeCanceled", o)
	}
	if o, _ := run(io.EOF, false); o != OutcomeRemoteFin {
		t.Fatalf("clean end: %v, want OutcomeRemoteFin", o)
	}
}
