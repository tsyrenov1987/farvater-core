package kilvater

import (
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
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

	if srv.overLimit(id) {
		t.Fatal("no streams open: should be allowed")
	}
	ks := m.openStream(id.Label())
	if !srv.overLimit(id) {
		t.Fatal("one stream open at cap 1: the next should be refused")
	}
	m.closeStream(ks)
	if srv.overLimit(id) {
		t.Fatal("stream closed: should be allowed again")
	}
}
