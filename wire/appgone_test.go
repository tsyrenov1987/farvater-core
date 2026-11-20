package wire

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// An app that drops a download half-way (a video scrubbed, a page left) makes
// the write to it fail while the path still delivers. That was filed as the
// transport failing: the switchboard read it as a reset on the path, and one
// reset trips the breaker and dethrones the leader.
func TestAppLeavingMidDownloadIsNotAPathError(t *testing.T) {
	for _, upFirst := range []bool{true, false} {
		app, client := net.Pipe()
		far, near := net.Pipe()
		go func() {
			buf := make([]byte, 4096)
			for {
				if _, err := far.Write(buf); err != nil {
					return
				}
			}
		}()
		up := make(chan []byte)
		go func() {
			io.ReadFull(app, make([]byte, 64*1024))
			if upFirst {
				close(up)
				time.Sleep(50 * time.Millisecond)
				app.Close()
			} else {
				app.Close()
				time.Sleep(50 * time.Millisecond)
				close(up)
			}
		}()
		out, err := runStream(context.Background(), near, near, near, up, client, discardMeter{})
		far.Close()
		if out != OutcomeClientFin {
			t.Fatalf("app left mid-download (its read side closed first: %v): %v %v, want OutcomeClientFin", upFirst, out, err)
		}
	}
}

type discardMeter struct{}

func (discardMeter) Up([]byte)   {}
func (discardMeter) Down([]byte) {}
