package switchboard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tsyrenov1987/farvater-core/brain"
)

// Status says how soon a path's flows had their answer: the median of the
// last half hour's, and of how many; a path nothing answered on says neither.
func TestStatusCarriesAnswerTime(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Ctx = "wifi"
	s, err := New(cfg, threeDead(t))
	if err != nil {
		t.Fatal(err)
	}
	s.probe = func(context.Context, []string) bool { return false }
	now := nowMs()
	for _, ms := range []int64{90, 400, 120} {
		s.observe(brain.Receipt{Path: "a", AtMs: now, WireReadyMs: 20, FirstByteMs: ms, AnswerMs: ms, Down: 2 * brain.KB, DownAtFail: -1, End: brain.EndRemoteFin, Dst: "h"})
	}
	// An hour old: out of the half hour.
	s.observe(brain.Receipt{Path: "b", AtMs: now - 60*60_000, WireReadyMs: 20, FirstByteMs: 50, AnswerMs: 50, Down: 2 * brain.KB, DownAtFail: -1, End: brain.EndRemoteFin, Dst: "h"})

	for _, p := range s.Status().Paths {
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		switch p.ID {
		case "a":
			if p.AnswerMs != 120 || p.AnswerN != 3 {
				t.Fatalf("path a: answer %d ms of %d, want 120 of 3", p.AnswerMs, p.AnswerN)
			}
		default:
			if strings.Contains(string(raw), "answer_") {
				t.Fatalf("path %s had no answer in the half hour, yet Status says\n%s", p.ID, raw)
			}
		}
	}
}
