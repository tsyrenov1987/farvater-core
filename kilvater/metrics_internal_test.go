package kilvater

import (
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A client that authenticates but never sends OPEN is counted once it is
// dropped at the OPEN deadline.
func TestMetricsOpenTimeout(t *testing.T) {
	old := openReadTimeout
	openReadTimeout = 50 * time.Millisecond
	t.Cleanup(func() { openReadTimeout = old })

	var kb Key
	rand.Read(kb[:])
	v := NewVerifier([]Key{kb})
	m := NewMetrics(v)
	srv := &Server{Verifier: v, Decoy: http.NotFoundHandler(), Metrics: m}

	path := "/connect"
	pr, pw := io.Pipe()
	defer pw.Close() // unblocks the leaked OPEN reader when the test ends
	req := httptest.NewRequest("POST", "https://kv.test"+path, pr)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: NewTag(kb, path, time.Now())})
	srv.ServeHTTP(httptest.NewRecorder(), req)

	if got := m.openTimeouts.Load(); got != 1 {
		t.Fatalf("open timeouts = %d, want 1", got)
	}
	if got := m.streamsOpen.Load(); got != 0 {
		t.Fatalf("streams open = %d after a timed-out stream, want 0", got)
	}
}

// The concurrent-stream cap refuses a key's next stream while it is at the
// limit, and lets it through again once a stream closes. It never cuts a
// running one.
func TestMetricsMaxStreamsPerKey(t *testing.T) {
	m := NewMetrics(nil)
	srv := &Server{Metrics: m, MaxStreamsPerKey: 1}
	id := Identity{V2: true, KeyID: KeyID{1, 2, 3}}

	now := time.Now()
	ks, ok := srv.admit(id, now)
	if !ok {
		t.Fatal("no streams open: should be allowed")
	}
	if _, ok := srv.admit(id, now); ok {
		t.Fatal("one stream open at cap 1: the next should be refused")
	}
	if got := ks.streamsOpen.Load(); got != 1 {
		t.Fatalf("streams open = %d after a refusal, want 1", got)
	}
	m.closeStream(ks)
	ks, ok = srv.admit(id, now)
	if !ok {
		t.Fatal("stream closed: should be allowed again")
	}
	m.closeStream(ks)
	// The shared v1 label is never capped.
	for i := 0; i < 3; i++ {
		if _, ok := srv.admit(Identity{}, now); !ok {
			t.Fatal("a v1 key was refused by the per-key cap")
		}
	}
}

// Streams arriving together cannot pass the cap between them: the check and
// the count are one step.
func TestMetricsMaxStreamsPerKeyAtOnce(t *testing.T) {
	m := NewMetrics(nil)
	srv := &Server{Metrics: m, MaxStreamsPerKey: 8}
	id := Identity{V2: true, KeyID: KeyID{4, 5, 6}}
	var wg sync.WaitGroup
	var let atomic.Int64
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := srv.admit(id, time.Now()); ok {
				let.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := let.Load(); got != 8 {
		t.Fatalf("%d streams admitted at once under a cap of 8", got)
	}
	if got := m.stat(id.Label()).streamsOpen.Load(); got != 8 {
		t.Fatalf("streams open = %d, want 8", got)
	}
}

// With a window, the volume cap counts what a key carried in the current
// window and lets the key back in when the next one starts.
func TestMetricsMaxBytesWindow(t *testing.T) {
	m := NewMetrics(nil)
	srv := &Server{Metrics: m, MaxBytesPerKey: 100, MaxBytesWindow: time.Hour}
	id := Identity{V2: true, KeyID: KeyID{7, 8, 9}}
	t0 := time.Now()
	ks, ok := srv.admit(id, t0)
	if !ok {
		t.Fatal("a fresh key was refused")
	}
	ks.addUp(60)
	ks.addDown(60)
	m.closeStream(ks)
	if _, ok := srv.admit(id, t0.Add(30*time.Minute)); ok {
		t.Fatal("over the cap inside the window: should be refused")
	}
	ks, ok = srv.admit(id, t0.Add(61*time.Minute))
	if !ok {
		t.Fatal("a new window began: should be allowed")
	}
	ks.addDown(99)
	m.closeStream(ks)
	if _, ok := srv.admit(id, t0.Add(62*time.Minute)); !ok {
		t.Fatal("99 of 100 in the new window: should be allowed")
	}
	// Without a window the cap is for the life of the process, as before.
	srv.MaxBytesWindow = 0
	if _, ok := srv.admit(id, t0.Add(48*time.Hour)); ok {
		t.Fatal("no window: 219 bytes over a cap of 100 should be refused")
	}
}
