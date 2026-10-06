package switchboard

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/brain"
	"github.com/tsyrenov1987/farvater-core/catalogue"
)

func threeDead(t *testing.T) *catalogue.Catalogue {
	t.Helper()
	var links []string
	for i, id := range []string{"a", "b", "c"} {
		links = append(links, "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:"+string(rune('1'+i))+"?security=tls&sni="+id+".example.com&type=tcp#"+id)
	}
	cat, err := catalogue.Parse([]byte(strings.Join(links, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

func delivered(path string) brain.Receipt {
	return brain.Receipt{Path: path, AtMs: nowMs(), WireReadyMs: 20, FirstByteMs: 30, Down: 64 * brain.KB, DownAtFail: -1, End: brain.EndRemoteFin, Dst: "h"}
}

func wireFailed(path string) brain.Receipt {
	return brain.Receipt{Path: path, AtMs: nowMs(), WireReadyMs: -1, FirstByteMs: -1, DownAtFail: -1, End: brain.EndTimeout, Dst: "h"}
}

func leaderOf(s *Switchboard) string {
	s.pick(nowMs(), "h", brain.DstTLS443)
	return s.Status().Leader
}

// What a session learned on a network is in the memory file for the next one;
// a network change mid-session switches to that network's memory with no
// restart, and back.
func TestMemoryFileCarriesNetworksAcrossSessions(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Ctx = "cell"
	cfg.MemoryFile = filepath.Join(t.TempDir(), "brain-memory.json")
	s, err := New(cfg, threeDead(t))
	if err != nil {
		t.Fatal(err)
	}
	s.probe = func(context.Context, []string) bool { return false }
	for i := 0; i < 6; i++ {
		s.observe(delivered("c"))
	}
	if err := s.SaveMemory(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfg.MemoryFile); err != nil {
		t.Fatalf("no memory file: %v", err)
	}

	next, err := New(cfg, threeDead(t))
	if err != nil {
		t.Fatal(err)
	}
	if l := leaderOf(next); l != "c" {
		t.Fatalf("next session on the same network: leader %q, want c", l)
	}
	next.SetNetwork("wifi:0a1b2c3d")
	if st := next.Status(); st.Ctx != "wifi:0a1b2c3d" || leaderOf(next) != "a" {
		t.Fatalf("on another network: ctx %q leader %q, want wifi:0a1b2c3d and a", st.Ctx, st.Leader)
	}
	next.observe(delivered("b"))
	if r := next.Receipts(); len(r) != 1 {
		t.Fatalf("receipts %d", len(r))
	}
	next.SetNetwork("cell")
	if l := leaderOf(next); l != "c" {
		t.Fatalf("back on cell: leader %q, want c", l)
	}
	if err := next.SaveMemory(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(cfg.MemoryFile)
	if !strings.Contains(string(raw), `"wifi:0a1b2c3d"`) || !strings.Contains(string(raw), `"cell"`) {
		t.Fatalf("both networks must be in the file: %s", raw)
	}
}

// No path connects and an allow-listed site answers directly: the network is
// restricted, and the brain moves to its restricted variant. One check per
// minute at most; a dead network (no answer) stays as it is; an answer that
// comes after the device changed networks is ignored.
func TestRestrictedNetworkCheck(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Ctx = "cell"
	s, err := New(cfg, threeDead(t))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	s.probe = func(_ context.Context, hosts []string) bool {
		calls.Add(1)
		return len(hosts) > 0
	}
	s.observe(wireFailed("a"))
	if calls.Load() != 0 {
		t.Fatal("one silent path is no reason to check")
	}
	s.observe(wireFailed("b"))
	waitCtx(t, s, "cell:wl")
	s.observe(wireFailed("c"))
	s.SetNetwork("cell")
	if st := s.Status(); st.Ctx != "cell:wl" || calls.Load() != 1 {
		t.Fatalf("ctx %q, checks %d: the same network must keep its restricted variant, one check", st.Ctx, calls.Load())
	}
	s.SetNetwork("wifi:0a1b2c3d")
	if st := s.Status(); st.Ctx != "wifi:0a1b2c3d" {
		t.Fatalf("ctx %q after moving to wifi", st.Ctx)
	}

	dead, _ := New(cfg, threeDead(t))
	calls.Store(0)
	dead.probe = func(context.Context, []string) bool { calls.Add(1); return false }
	dead.observe(wireFailed("a"))
	dead.observe(wireFailed("b"))
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		dead.mu.Lock()
		done := !dead.probing
		dead.mu.Unlock()
		if done && calls.Load() == 1 {
			break
		}
	}
	for _, p := range []string{"c", "a", "b"} {
		dead.observe(wireFailed(p))
	}
	time.Sleep(100 * time.Millisecond)
	if st := dead.Status(); st.Ctx != "cell" || calls.Load() != 1 {
		t.Fatalf("dead network: ctx %q, checks %d; want cell and one check a minute", st.Ctx, calls.Load())
	}

	late, _ := New(cfg, threeDead(t))
	release := make(chan struct{})
	late.probe = func(context.Context, []string) bool { <-release; return true }
	late.observe(wireFailed("a"))
	late.observe(wireFailed("b"))
	late.SetNetwork("wifi:0a1b2c3d")
	close(release)
	time.Sleep(100 * time.Millisecond)
	if st := late.Status(); st.Ctx != "wifi:0a1b2c3d" {
		t.Fatalf("a check that answered after the network changed moved the brain: ctx %q", st.Ctx)
	}
}

func waitCtx(t *testing.T, s *Switchboard, want string) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if s.Status().Ctx == want {
			return
		}
	}
	t.Fatalf("ctx %q, want %q", s.Status().Ctx, want)
}
