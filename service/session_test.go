package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/catalogue"
	"github.com/tsyrenov1987/farvater-core/desktop"
	"github.com/tsyrenov1987/farvater-core/switchboard"
)

const (
	pathA = "vless://00000000-0000-0000-0000-000000000000@192.0.2.1:9?security=tls&sni=example.com&type=tcp#a"
	pathB = "vless://00000000-0000-0000-0000-000000000000@192.0.2.2:9?security=tls&sni=example.com&type=tcp#b"
)

type fakeSystem struct{ down atomic.Int32 }

func (f *fakeSystem) ReadPacket([]byte) (int, error) { select {} }
func (f *fakeSystem) WritePacket([]byte) error       { return nil }
func (f *fakeSystem) Down()                          { f.down.Add(1) }

// world is a machine and a network the test controls.
type world struct {
	t *testing.T

	mu      sync.Mutex
	body    string
	fetched []string
	fetch   func(url string) error
	proofs  []Proof // nil-exhausted: prove OK forever
	proved  int

	upErr, serveErr error
	ups             atomic.Int32
	sys             *fakeSystem
	tick            chan time.Time
	proving         chan struct{}
	block           chan struct{} // a Prove that waits for the test
}

func newWorld(t *testing.T) *world {
	return &world{t: t, body: pathA, sys: &fakeSystem{}, tick: make(chan time.Time), proving: make(chan struct{}, 64)}
}

func (w *world) hooks() Hooks {
	return Hooks{
		Fetch: func(url string) ([]byte, *catalogue.Provider, error) {
			w.mu.Lock()
			defer w.mu.Unlock()
			w.fetched = append(w.fetched, url)
			if w.fetch != nil {
				if err := w.fetch(url); err != nil {
					return nil, nil, err
				}
			}
			return []byte(w.body), &catalogue.Provider{Title: "Club"}, nil
		},
		Up: func(nodes []netip.Addr, _ func(string, ...any)) (System, error) {
			w.ups.Add(1)
			if w.upErr != nil {
				return nil, w.upErr
			}
			return w.sys, nil
		},
		Serve: func(context.Context, System, desktop.Conns, string, string, func(string, ...any)) error {
			return w.serveErr
		},
		Prove: func(ctx context.Context, _ *switchboard.Switchboard, _, _, _ string) Proof {
			w.proving <- struct{}{}
			if w.block != nil {
				select {
				case <-w.block:
				case <-ctx.Done():
					return Proof{Error: "cancelled"}
				}
			}
			w.mu.Lock()
			defer w.mu.Unlock()
			if w.proved < len(w.proofs) {
				w.proved++
				return w.proofs[w.proved-1]
			}
			return Proof{OK: true, Path: "a", Rail: "tls"}
		},
		Sleep: func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil },
		After: func(time.Duration) <-chan time.Time { return w.tick },
	}
}

func (w *world) refreshNow(t *testing.T, s *Session, want func(*Session) bool) {
	t.Helper()
	select {
	case w.tick <- time.Now():
	case <-time.After(5 * time.Second):
		t.Fatal("refresh loop is not waiting")
	}
	waitFor(t, "refresh", func() bool { return want(s) })
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func waitState(t *testing.T, s *Session, want string) State {
	t.Helper()
	waitFor(t, "state "+want, func() bool { return s.CurrentState().State == want })
	return s.CurrentState()
}

func session(t *testing.T, w *world, code bool) *Session {
	t.Helper()
	s := New(t.TempDir(), w.hooks(), t.Logf)
	if code {
		s.prefs.Source = "https://joinorden.com/hsub/ORDEN-AAAAA-BBBBB"
	}
	t.Cleanup(func() { s.Close(false) })
	return s
}

func TestMain(m *testing.M) {
	drainTick = 10 * time.Millisecond
	os.Exit(m.Run())
}

func TestNoCode(t *testing.T) {
	w := newWorld(t)
	s := session(t, w, false)
	s.Connect()
	st := waitState(t, s, "failed")
	if st.Reason != reasonNoCatalogue || w.ups.Load() != 0 {
		t.Fatalf("%+v ups=%d", st, w.ups.Load())
	}
}

func TestCatalogueFails(t *testing.T) {
	w := newWorld(t)
	w.fetch = func(string) error { return errors.New("catalogue: HTTP 502") }
	s := session(t, w, true)
	s.Connect()
	st := waitState(t, s, "failed")
	if st.Reason != reasonCatalogue || !strings.Contains(st.Detail, "502") {
		t.Fatalf("%+v", st)
	}
	want := []string{"https://cdn2.cdn-tvzvezda-ru.ru/api/hsub/ORDEN-AAAAA-BBBBB", "https://viporden.online/hsub/ORDEN-AAAAA-BBBBB", "https://myorden.ru/hsub/ORDEN-AAAAA-BBBBB", "https://joinorden.com/hsub/ORDEN-AAAAA-BBBBB"}
	if strings.Join(w.fetched, " ") != strings.Join(want, " ") {
		t.Fatalf("mirrors %v", w.fetched)
	}
}

func TestSettledAnswerStopsMirrors(t *testing.T) {
	w := newWorld(t)
	w.fetch = func(string) error { return errors.New("catalogue: HTTP 404") }
	s := session(t, w, true)
	s.Connect()
	st := waitState(t, s, "failed")
	// The plain door's 404 is not taken for the answer; the next mirror's is.
	if len(w.fetched) != 2 || !strings.Contains(st.Detail, "Такого кода нет") {
		t.Fatalf("%v %+v", w.fetched, st)
	}
}

func TestSavedCopyThenFreshRemovesTheNote(t *testing.T) {
	w := newWorld(t)
	fail := true
	w.fetch = func(string) error {
		if fail {
			return errors.New("offline")
		}
		return nil
	}
	s := session(t, w, true)
	s.prefs.Text = pathA
	s.Connect()
	st := waitState(t, s, "on")
	if !st.FromSaved {
		t.Fatalf("%+v", st)
	}
	w.mu.Lock()
	fail = false
	w.mu.Unlock()
	w.refreshNow(t, s, func(s *Session) bool { return !s.CurrentState().FromSaved })
}

func TestRoutesOnlyAfterProof(t *testing.T) {
	w := newWorld(t)
	w.proofs = []Proof{{Error: "first"}, {Error: "second"}}
	s := session(t, w, true)
	s.Connect()
	st := waitState(t, s, "on")
	if w.ups.Load() != 1 || w.proved != 2 || st.Proof == nil || !st.Proof.OK || st.SinceMs == 0 {
		t.Fatalf("%+v ups=%d proved=%d", st, w.ups.Load(), w.proved)
	}
	s.Disconnect()
	waitFor(t, "down", func() bool { return w.sys.down.Load() == 1 })
}

func TestProvingShowsAttemptAndError(t *testing.T) {
	w := newWorld(t)
	w.block = make(chan struct{})
	w.proofs = []Proof{{Error: "reset"}}
	s := session(t, w, true)
	s.Connect()
	<-w.proving
	if st := waitState(t, s, "proving"); st.Attempt != 1 || st.Error != "" {
		t.Fatalf("%+v", st)
	}
	w.block <- struct{}{}
	<-w.proving
	waitFor(t, "attempt 2", func() bool { st := s.CurrentState(); return st.Attempt == 2 && st.Error == "reset" })
	if w.ups.Load() != 0 {
		t.Fatal("routed before a delivery was proved")
	}
}

func TestUpFails(t *testing.T) {
	w := newWorld(t)
	w.upErr = errors.New("wintun")
	s := session(t, w, true)
	s.Connect()
	if st := waitState(t, s, "failed"); st.Reason != reasonEstablish || st.Detail != "wintun" {
		t.Fatalf("%+v", st)
	}
}

func TestEngineFailsPutsMachineBack(t *testing.T) {
	w := newWorld(t)
	w.serveErr = errors.New("stack")
	s := session(t, w, true)
	s.Connect()
	if st := waitState(t, s, "failed"); st.Reason != reasonTunnel {
		t.Fatalf("%+v", st)
	}
	waitFor(t, "down", func() bool { return w.sys.down.Load() == 1 })
}

func TestDisconnectWhileProvingStaysOff(t *testing.T) {
	w := newWorld(t)
	w.block = make(chan struct{})
	s := session(t, w, true)
	s.Connect()
	<-w.proving
	s.Disconnect()
	if st := s.CurrentState(); st.State != "off" {
		t.Fatalf("%+v", st)
	}
	s.mu.Lock()
	done := s.done
	s.mu.Unlock()
	<-done
	if st := s.CurrentState(); st.State != "off" || w.ups.Load() != 0 {
		t.Fatalf("%+v ups=%d", st, w.ups.Load())
	}
}

func TestReconnectWaitsForThePreviousTeardown(t *testing.T) {
	w := newWorld(t)
	s := session(t, w, true)
	s.Connect()
	waitState(t, s, "on")
	s.Connect()
	waitFor(t, "second up", func() bool { return w.ups.Load() == 2 })
	if w.sys.down.Load() != 1 {
		t.Fatalf("down=%d when the second tunnel came up", w.sys.down.Load())
	}
	waitState(t, s, "on")
}

func TestCatalogueSwapsUnderTheTunnel(t *testing.T) {
	w := newWorld(t)
	s := session(t, w, true)
	s.Connect()
	waitState(t, s, "on")
	s.mu.Lock()
	l := s.live
	s.mu.Unlock()
	before := l.current()

	w.refreshNow(t, s, func(*Session) bool { return true })
	time.Sleep(50 * time.Millisecond)
	if l.current() != before {
		t.Fatal("the same paths replaced the switchboard")
	}

	w.mu.Lock()
	w.body = pathA + "\n" + pathB
	w.mu.Unlock()
	w.refreshNow(t, s, func(*Session) bool { return l.current() != before })
	if n := len(l.current().Paths()); n != 2 || w.ups.Load() != 1 || w.sys.down.Load() != 0 {
		t.Fatalf("paths=%d ups=%d down=%d", n, w.ups.Load(), w.sys.down.Load())
	}
	if !strings.Contains(s.status(), `"paths"`) {
		t.Fatalf("status = %s", s.status())
	}
}

func TestResume(t *testing.T) {
	w := newWorld(t)
	s := session(t, w, true)
	s.Resume()
	time.Sleep(20 * time.Millisecond)
	if st := s.CurrentState(); st.State != "off" {
		t.Fatalf("connected on its own: %+v", st)
	}
	s.prefs.Autostart = true
	s.Resume()
	waitState(t, s, "on")
}

func TestLeftOnComesBackAfterACrashNotAfterShutdown(t *testing.T) {
	dir := t.TempDir()
	w := newWorld(t)
	s := New(dir, w.hooks(), t.Logf)
	s.prefs.Source = "https://joinorden.com/hsub/ORDEN-AAAAA-BBBBB"
	s.Connect()
	waitState(t, s, "on")

	again := New(dir, newWorld(t).hooks(), t.Logf) // the process died here
	if !again.prefs.Wanted {
		t.Fatal("a connection left on was not remembered")
	}

	s.Close(true)
	after := New(dir, newWorld(t).hooks(), t.Logf)
	if after.prefs.Wanted {
		t.Fatal("a shutdown left the connection wanted")
	}
}

func TestDisconnectIsRemembered(t *testing.T) {
	dir := t.TempDir()
	w := newWorld(t)
	s := New(dir, w.hooks(), t.Logf)
	s.prefs.Source = "https://joinorden.com/hsub/ORDEN-AAAAA-BBBBB"
	s.Connect()
	waitState(t, s, "on")
	s.Disconnect()
	s.Close(false)
	if New(dir, newWorld(t).hooks(), t.Logf).prefs.Wanted {
		t.Fatal("still wanted after disconnect")
	}
}

func call(t *testing.T, s *Session, req string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(s.Handle([]byte(req)), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestImportOnlyOrden(t *testing.T) {
	w := newWorld(t)
	s := session(t, w, false)
	for _, in := range []string{
		"https://evil.example/hsub/ORDEN-AAAAA-BBBBB",
		"http://joinorden.com/hsub/ORDEN-AAAAA-BBBBB",
		"https://joinorden.com.evil.example/hsub/X",
		"https://joinorden.com/cabinet",
		"https://joinorden.com/hsub/X?redirect=https://evil.example",
		"https://joinorden.com/hsub/../admin/x",
		pathA,
		"ORDEN-ORDEN-AAAAA-BBBBB-CCCCC",
		"",
	} {
		if out := call(t, s, `{"op":"import","input":`+string(toJSON(in))+`}`); out["ok"] != false {
			t.Errorf("%q accepted: %v", in, out)
		}
	}
	if len(w.fetched) != 0 {
		t.Fatalf("fetched %v", w.fetched)
	}
}

func TestSourceForms(t *testing.T) {
	const want = "https://joinorden.com/hsub/ORDEN-AB1CD-23EFG"
	for _, in := range []string{
		"ORDEN-AB1CD-23EFG",
		"orden-ab1cd-23efg",
		"  ab1cd 23efg ",
		"AB1CD23EFG",
		"ORDEN_AB1CD_23EFG",
		"ORDEN—AB1CD–23EFG",
		"​ORDEN-AB1CD-23EFG­",
		"ORDEN-АВ1CD-23ЕFG", // Cyrillic А, В, Е
	} {
		if got, err := Source(in); err != nil || got != want {
			t.Errorf("%q = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"https://myorden.ru/hsub/ORDEN-AB1CD-23EFG", "https://www.viporden.online/sub/abc"} {
		if got, err := Source(in); err != nil || got != in {
			t.Errorf("%q = %q, %v", in, got, err)
		}
	}
}

func TestSaveTakesOnlyWhatImportChecked(t *testing.T) {
	w := newWorld(t)
	s := session(t, w, false)
	if out := call(t, s, `{"op":"save","source":"https://joinorden.com/hsub/ORDEN-AAAAA-BBBBB"}`); out["ok"] != false {
		t.Fatalf("saved with no import: %v", out)
	}
	out := call(t, s, `{"op":"import","input":"https://myorden.ru/hsub/ORDEN-AAAAA-BBBBB"}`)
	if out["ok"] != true || out["paths"] != float64(1) || out["source"] != "https://myorden.ru/hsub/ORDEN-AAAAA-BBBBB" {
		t.Fatalf("%v", out)
	}
	if p, ok := out["provider"].(map[string]any); !ok || p["title"] != "Club" {
		t.Fatalf("provider must be an object: %v", out["provider"])
	}
	if len(w.fetched) != 1 {
		t.Fatalf("one import is one fetch: %v", w.fetched)
	}
	if out := call(t, s, `{"op":"save","source":"https://evil.example/x"}`); out["ok"] != false {
		t.Fatalf("%v", out)
	}
	if out := call(t, s, `{"op":"save","source":"https://myorden.ru/hsub/ORDEN-AAAAA-BBBBB"}`); out["ok"] != true {
		t.Fatalf("%v", out)
	}
	p := call(t, s, `{"op":"prefs"}`)
	if p["source"] != "https://myorden.ru/hsub/ORDEN-AAAAA-BBBBB" || p["paths"] != float64(1) || p["autostart"] != false {
		t.Fatalf("%v", p)
	}
	if prov, ok := p["provider"].(string); !ok || !strings.Contains(prov, `"title":"Club"`) {
		t.Fatalf("provider must be a string of JSON: %v", p["provider"])
	}
	if _, has := p["text"]; has {
		t.Fatal("the catalogue must not leave the service")
	}
}

func TestImportExplainsAndKeepsTheStatusForMirrors(t *testing.T) {
	w := newWorld(t)
	w.fetch = func(string) error { return errors.New("catalogue: HTTP 404") }
	s := session(t, w, false)
	out := call(t, s, `{"op":"import","input":"ORDEN-AAAAA-BBBBB"}`)
	e, _ := out["error"].(string)
	if out["ok"] != false || !strings.Contains(e, "Такого кода нет") || !strings.Contains(e, "HTTP 404") {
		t.Fatalf("%v", out)
	}
}

func TestProtocol(t *testing.T) {
	w := newWorld(t)
	s := session(t, w, true)
	if st := call(t, s, `{"op":"state"}`); st["state"] != "off" {
		t.Fatalf("%v", st)
	}
	if st := call(t, s, `{"op":"status"}`); st["text"] != "{}" {
		t.Fatalf("%v", st)
	}
	if v := call(t, s, `{"op":"version"}`); v["text"] != Version {
		t.Fatalf("%v", v)
	}
	if p := call(t, s, `{"op":"progress"}`); p["text"] != `{"bytes":0,"total":0}` {
		t.Fatalf("%v", p)
	}
	if out := call(t, s, `{"op":"autostart","on":true}`); out["ok"] != true || !s.prefs.Autostart {
		t.Fatalf("%v", out)
	}
	if out := call(t, s, `{"op":"nonsense"}`); out["ok"] != false {
		t.Fatalf("%v", out)
	}
	if out := call(t, s, `not json`); out["ok"] != false {
		t.Fatalf("%v", out)
	}
	if out := call(t, s, `{"op":"connect"}`); out["ok"] != true {
		t.Fatalf("%v", out)
	}
	waitState(t, s, "on")
	st := call(t, s, `{"op":"state"}`)
	proof, _ := st["proof"].(map[string]any)
	if st["state"] != "on" || proof["ok"] != true || proof["path"] != "a" || st["since_ms"] == nil {
		t.Fatalf("%v", st)
	}
	if out := call(t, s, `{"op":"disconnect"}`); out["ok"] != true || s.CurrentState().State != "off" {
		t.Fatalf("%v", out)
	}
}

func TestEveryMs(t *testing.T) {
	for _, c := range []struct {
		h    int
		want time.Duration
	}{{0, time.Hour}, {1, time.Hour}, {2, 2 * time.Hour}, {99, 12 * time.Hour}} {
		if got := everyMs(&catalogue.Provider{UpdateHours: c.h}); got != c.want {
			t.Errorf("%d: %v", c.h, got)
		}
	}
	if everyMs(nil) != time.Hour {
		t.Error("nil")
	}
}
