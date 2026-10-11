package kilvater_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/kilvater"
)

// tcpEcho is a loopback TCP echo for the tunnel to dial.
func tcpEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

// echoFlow drives one whole TCP tunnel flow through srv.ServeHTTP: OPEN to the
// echo, one DATA frame up, CLOSE. It returns once the flow has fully ended
// (ServeHTTP returned, both pump goroutines joined), so the metrics are settled.
func echoFlow(t *testing.T, srv *kilvater.Server, tag, path, echo string, payload []byte) *httptest.ResponseRecorder {
	t.Helper()
	open := []byte{kilvater.NetTCP}
	open, err := kilvater.AppendAddr(open, echo)
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	kilvater.WriteFrame(&body, kilvater.FrameOpen, open)
	kilvater.WriteFrame(&body, kilvater.FrameData, payload)
	kilvater.WriteFrame(&body, kilvater.FrameClose, []byte{0})

	req := httptest.NewRequest("POST", "https://kv.test"+path, &body)
	req.AddCookie(&http.Cookie{Name: kilvater.CookieName, Value: tag})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func promText(m *kilvater.Metrics) string {
	var b strings.Builder
	m.WritePrometheus(&b)
	return b.String()
}

func v2Server(t *testing.T, sub string) (*kilvater.Server, *kilvater.Metrics, kilvater.KeyID, kilvater.Key) {
	t.Helper()
	var master kilvater.Key
	rand.Read(master[:])
	id := kilvater.KeyIDFor(master, []byte(sub))
	k := kilvater.DeriveKey(master, id)
	v := kilvater.NewVerifierConfig(kilvater.VerifierConfig{Master: &master})
	m := kilvater.NewMetrics(v)
	srv := &kilvater.Server{Verifier: v, Decoy: http.NotFoundHandler(), AllowPrivate: true, Metrics: m}
	return srv, m, id, k
}

// Bytes and streams are counted and exported under the key's id.
func TestMetricsCountsBytesAndStreamsByKeyID(t *testing.T) {
	srv, m, id, k := v2Server(t, "sub-1")
	echo, path := tcpEcho(t), "/connect"
	tag := kilvater.NewTagV2(id, k, path, time.Now())
	echoFlow(t, srv, tag, path, echo, bytes.Repeat([]byte("z"), 100))

	out := promText(m)
	kid := id.String()
	for _, want := range []string{
		"\nkilvater_streams_total 1\n",
		"\nkilvater_up_bytes_total 100\n",
		"\nkilvater_down_bytes_total 100\n",
		`kilvater_key_up_bytes_total{key="` + kid + `"} 100`,
		`kilvater_key_down_bytes_total{key="` + kid + `"} 100`,
		`kilvater_key_streams_total{key="` + kid + `"} 1`,
		`kilvater_key_streams_open{key="` + kid + `"} 0`,
		"# TYPE kilvater_up_bytes_total counter",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q\n---\n%s", want, out)
		}
	}
}

// The export names the key id but never the key bytes, the master, or a target
// address.
func TestMetricsHidesKeyMaterialAndAddresses(t *testing.T) {
	srv, m, id, k := v2Server(t, "sub-x")
	echo, path := tcpEcho(t), "/connect"
	echoFlow(t, srv, kilvater.NewTagV2(id, k, path, time.Now()), path, echo, []byte("hello"))

	out := promText(m)
	if !strings.Contains(out, id.String()) {
		t.Fatal("the key id should appear as a label")
	}
	for name, secret := range map[string]string{
		"derived key":    hex.EncodeToString(k[:]),
		"target address": echo,
	} {
		if strings.Contains(out, secret) {
			t.Errorf("metrics leaked the %s (%q)\n---\n%s", name, secret, out)
		}
	}
}

// A tag cookie that does not verify is an auth failure; a tag used twice is a
// replay. Neither opens a stream.
func TestMetricsCountsAuthFailuresAndReplays(t *testing.T) {
	key := testKey(t)
	v := kilvater.NewVerifier([]kilvater.Key{key})
	m := kilvater.NewMetrics(v)
	srv := &kilvater.Server{Verifier: v, Decoy: http.NotFoundHandler(), AllowPrivate: true, Metrics: m}
	echo, path := tcpEcho(t), "/connect"

	bad := httptest.NewRequest("POST", "https://kv.test"+path, nil)
	bad.AddCookie(&http.Cookie{Name: kilvater.CookieName, Value: "garbage"})
	srv.ServeHTTP(httptest.NewRecorder(), bad)

	tag := kilvater.NewTag(key, path, time.Now())
	echoFlow(t, srv, tag, path, echo, []byte("hi")) // first use: a real stream
	echoFlow(t, srv, tag, path, echo, []byte("hi")) // same tag again: a replay

	out := promText(m)
	for _, want := range []string{
		"\nkilvater_auth_failures_total 2\n", // the garbage tag and the replay
		"\nkilvater_replay_hits_total 1\n",
		"\nkilvater_streams_total 1\n", // only the first use opened a stream
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q\n---\n%s", want, out)
		}
	}
}

// The endpoint serves the text at /metrics and 404s elsewhere, so it can run on
// its own listener.
func TestMetricsEndpointServesPrometheus(t *testing.T) {
	m := kilvater.NewMetrics(nil)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "kilvater_streams_total") {
		t.Fatalf("/metrics: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content-type %q, want text/plain", ct)
	}
	rec = httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 404 {
		t.Errorf("a non-/metrics path returned %d, want 404", rec.Code)
	}
}

// A per-key volume cap refuses the key's next stream once it is over, counting a
// limit reject, and never opens that stream.
func TestMetricsMaxBytesPerKeyRefusesNewStreams(t *testing.T) {
	srv, m, id, k := v2Server(t, "sub-l")
	srv.MaxBytesPerKey = 150
	echo, path := tcpEcho(t), "/connect"

	// 100 up + 100 down = 200 bytes, past the 150 cap.
	echoFlow(t, srv, kilvater.NewTagV2(id, k, path, time.Now()), path, echo, bytes.Repeat([]byte("z"), 100))
	// A fresh (non-replay) tag for the same key is now refused by the cap.
	echoFlow(t, srv, kilvater.NewTagV2(id, k, path, time.Now()), path, echo, []byte("more"))

	out := promText(m)
	for _, want := range []string{
		"\nkilvater_streams_total 1\n", // the second stream never opened
		"\nkilvater_limit_rejects_total 1\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q\n---\n%s", want, out)
		}
	}
}
