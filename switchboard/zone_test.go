package switchboard

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// On a cellular network the network itself is asked, allow-listed and foreign
// sites side by side: two probes with no foreign answer are a zone; Wi-Fi is
// not asked.
func TestZoneCheck(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Ctx = "cell:25001"
	s, err := New(cfg, threeDead(t))
	if err != nil {
		t.Fatal(err)
	}
	var asked atomic.Int32
	var foreign atomic.Int32
	s.probe = func(context.Context, []string) bool { return true }
	s.count = func(_ context.Context, hosts []string) int {
		if len(hosts) != len(cfg.ControlProbes) {
			t.Errorf("asked %v, want the control sites", hosts)
		}
		asked.Add(1)
		return int(foreign.Load())
	}
	wait := func(n int32) {
		t.Helper()
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
			s.mu.Lock()
			out := s.zprobing
			s.mu.Unlock()
			if asked.Load() == n && !out {
				return
			}
		}
		t.Fatalf("asked %d times, want %d", asked.Load(), n)
	}
	s.observe(wireFailed("a"))
	wait(1)
	if v := s.Status().Verdict; v != "" {
		t.Fatalf("verdict %q after one probe", v)
	}
	s.observe(wireFailed("a"))
	wait(1) // not again within ProbeUnsureMs
	s.mu.Lock()
	s.zprobed -= 10_000
	s.mu.Unlock()
	s.observe(wireFailed("a"))
	wait(2)
	if v := s.Status().Verdict; v != "zone" {
		t.Fatalf("verdict %q after two probes with no foreign answer", v)
	}
	foreign.Store(3)
	for n := int32(3); n <= 4; n++ {
		s.mu.Lock()
		s.zprobed -= 120_000
		s.mu.Unlock()
		s.observe(wireFailed("a"))
		wait(n)
	}
	if v := s.Status().Verdict; v != "open" {
		t.Fatalf("verdict %q after two probes with foreign answers", v)
	}

	cfg.Ctx = "wifi:0a1b2c3d"
	w, err := New(cfg, threeDead(t))
	if err != nil {
		t.Fatal(err)
	}
	w.probe = func(context.Context, []string) bool { return true }
	w.count = func(context.Context, []string) int { t.Error("wifi asked"); return 0 }
	w.observe(wireFailed("a"))
	time.Sleep(50 * time.Millisecond)
}
