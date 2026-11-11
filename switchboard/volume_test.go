package switchboard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/brain"
	"github.com/tsyrenov1987/farvater-core/wire"
)

// Status says at what volume a path's flows and shared connections ended, each
// list cut short after its last step that counted anything; a path where
// nothing has ended carries no such block at all.
func TestStatusCarriesVolumeAtEnd(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Ctx = "cell"
	s, err := New(cfg, threeDead(t))
	if err != nil {
		t.Fatal(err)
	}
	s.probe = func(context.Context, []string) bool { return false }
	now := nowMs()
	s.observe(brain.Receipt{Path: "a", AtMs: now, WireReadyMs: 20, FirstByteMs: 40, Down: 20 * brain.KB, DownAtFail: 20 * brain.KB, End: brain.EndStallAbandon, Dst: "h"})
	s.observe(brain.Receipt{Path: "a", AtMs: now, WireReadyMs: 20, FirstByteMs: 40, Down: 300 * brain.KB, DownAtFail: 300 * brain.KB, End: brain.EndWireReset, Dst: "h"})
	s.observe(brain.Receipt{Path: "a", AtMs: now, WireReadyMs: 20, FirstByteMs: 40, Down: 2 * brain.KB, DownAtFail: -1, End: brain.EndRemoteFin, Dst: "h"})
	s.noteConnEnd("a", wire.ConnEndDead, 5<<20, time.Now().Add(-time.Second))
	s.noteConnEnd("a", wire.ConnEndOurs, 100, time.Now().Add(-time.Second))

	var a, b PathStatus
	for _, p := range s.Status().Paths {
		switch p.ID {
		case "a":
			a = p
		case "b":
			b = p
		}
	}
	if b.Vol != nil {
		t.Fatalf("path b ended nothing, yet carries %+v", *b.Vol)
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	want := `"vol":{"flow_reset":[0,0,0,0,1],"flow_stall":[0,0,1],"flow_ended":[1],"conn_ours":[1],"conn_dead":[0,0,0,0,0,1]}`
	if !strings.Contains(string(raw), want) {
		t.Fatalf("path a in Status:\n%s\nwant it to hold\n%s", raw, want)
	}
}
