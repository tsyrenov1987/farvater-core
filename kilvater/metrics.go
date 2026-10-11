package kilvater

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
)

// Metrics counts traffic and health for a Server, exported in Prometheus text
// form. Per-key counters are labelled by a key's identity (the v2 key id, or
// "v1" for the shared flat key) — never the key bytes, and never a target
// address. All methods are safe on a nil *Metrics, so a Server without metrics
// pays nothing and needs no guards at the call sites.
type Metrics struct {
	mu   sync.Mutex
	keys map[string]*keyStat

	connsTotal    atomic.Int64
	connsOpen     atomic.Int64
	handshakeFail atomic.Int64
	streamsTotal  atomic.Int64
	streamsOpen   atomic.Int64
	authFailures  atomic.Int64
	limitRejects  atomic.Int64
	openTimeouts  atomic.Int64
	upBytes       atomic.Int64
	downBytes     atomic.Int64

	verifier *Verifier
}

// keyStat is one key's running totals. It holds a back-pointer so a byte count
// rolls up into the global total in the same call.
type keyStat struct {
	m           *Metrics
	up, down    atomic.Int64
	streams     atomic.Int64 // opened over the process's life
	streamsOpen atomic.Int64 // active now
}

func (ks *keyStat) addUp(n int) {
	if ks == nil {
		return
	}
	ks.up.Add(int64(n))
	ks.m.upBytes.Add(int64(n))
}

func (ks *keyStat) addDown(n int) {
	if ks == nil {
		return
	}
	ks.down.Add(int64(n))
	ks.m.downBytes.Add(int64(n))
}

// NewMetrics makes a metrics sink. v, if given, supplies the replay-hit count
// (the verifier owns the replay cache); it may be nil.
func NewMetrics(v *Verifier) *Metrics {
	return &Metrics{keys: map[string]*keyStat{}, verifier: v}
}

// stat returns the per-key counters for label, creating them on first use. Only
// an authenticated key reaches here, so the label set stays bounded by the
// subscribers that actually connected.
func (m *Metrics) stat(label string) *keyStat {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ks := m.keys[label]
	if ks == nil {
		ks = &keyStat{m: m}
		m.keys[label] = ks
	}
	return ks
}

// openStream records a new stream for label and returns its counters.
func (m *Metrics) openStream(label string) *keyStat {
	if m == nil {
		return nil
	}
	m.streamsTotal.Add(1)
	m.streamsOpen.Add(1)
	ks := m.stat(label)
	ks.streams.Add(1)
	ks.streamsOpen.Add(1)
	return ks
}

// closeStream records that a stream opened with openStream has ended.
func (m *Metrics) closeStream(ks *keyStat) {
	if ks == nil {
		return
	}
	ks.m.streamsOpen.Add(-1)
	ks.streamsOpen.Add(-1)
}

func (m *Metrics) authFail() {
	if m != nil {
		m.authFailures.Add(1)
	}
}

func (m *Metrics) limitReject() {
	if m != nil {
		m.limitRejects.Add(1)
	}
}

func (m *Metrics) openTimeout() {
	if m != nil {
		m.openTimeouts.Add(1)
	}
}

// HandshakeFailed records a TLS handshake that did not complete, from the
// listener that handshakes before net/http sees the connection.
func (m *Metrics) HandshakeFailed() {
	if m != nil {
		m.handshakeFail.Add(1)
	}
}

// ConnState tracks connection lifecycle, for http.Server.ConnState. Only a
// connection that completed its TLS handshake reaches net/http, so these count
// established connections; failed handshakes are counted by HandshakeFailed.
func (m *Metrics) ConnState(c net.Conn, state http.ConnState) {
	if m == nil {
		return
	}
	switch state {
	case http.StateNew:
		m.connsTotal.Add(1)
		m.connsOpen.Add(1)
	case http.StateClosed:
		m.connsOpen.Add(-1)
	}
}

// ServeHTTP exposes the metrics at /metrics in Prometheus text format and 404s
// elsewhere, so it can run on its own loopback listener.
func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/metrics" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	m.WritePrometheus(w)
}

// WritePrometheus writes the current counters in Prometheus text format.
func (m *Metrics) WritePrometheus(w io.Writer) {
	if m == nil {
		return
	}
	var replays int64
	if m.verifier != nil {
		replays = m.verifier.Replays()
	}
	for _, s := range []struct {
		name, typ, help string
		val             int64
	}{
		{"kilvater_connections_total", "counter", "TCP connections accepted", m.connsTotal.Load()},
		{"kilvater_connections_open", "gauge", "TCP connections open now", m.connsOpen.Load()},
		{"kilvater_handshake_failures_total", "counter", "TLS handshakes that did not complete", m.handshakeFail.Load()},
		{"kilvater_streams_total", "counter", "tunnel streams opened", m.streamsTotal.Load()},
		{"kilvater_streams_open", "gauge", "tunnel streams open now", m.streamsOpen.Load()},
		{"kilvater_auth_failures_total", "counter", "requests with a tag cookie that did not verify", m.authFailures.Load()},
		{"kilvater_replay_hits_total", "counter", "tags rejected as replays", replays},
		{"kilvater_open_timeouts_total", "counter", "authenticated streams that never sent OPEN in time", m.openTimeouts.Load()},
		{"kilvater_limit_rejects_total", "counter", "streams refused by a per-key limit", m.limitRejects.Load()},
		{"kilvater_up_bytes_total", "counter", "payload bytes from clients to targets", m.upBytes.Load()},
		{"kilvater_down_bytes_total", "counter", "payload bytes from targets to clients", m.downBytes.Load()},
	} {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %d\n", s.name, s.help, s.name, s.typ, s.name, s.val)
	}

	// Per-key counters, sorted so the output is stable.
	m.mu.Lock()
	labels := make([]string, 0, len(m.keys))
	for l := range m.keys {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	type row struct {
		label                        string
		up, down, streams, streamsUp int64
	}
	rows := make([]row, 0, len(labels))
	for _, l := range labels {
		ks := m.keys[l]
		rows = append(rows, row{l, ks.up.Load(), ks.down.Load(), ks.streams.Load(), ks.streamsOpen.Load()})
	}
	m.mu.Unlock()

	for _, s := range []struct {
		name, typ, help string
		get             func(row) int64
	}{
		{"kilvater_key_up_bytes_total", "counter", "payload bytes from a key's clients to targets", func(r row) int64 { return r.up }},
		{"kilvater_key_down_bytes_total", "counter", "payload bytes from targets to a key's clients", func(r row) int64 { return r.down }},
		{"kilvater_key_streams_total", "counter", "tunnel streams opened by a key", func(r row) int64 { return r.streams }},
		{"kilvater_key_streams_open", "gauge", "a key's tunnel streams open now", func(r row) int64 { return r.streamsUp }},
	} {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", s.name, s.help, s.name, s.typ)
		for _, r := range rows {
			// %q quotes and escapes the label; our labels are hex or "v1", pure
			// ASCII, so the result is Prometheus-valid.
			fmt.Fprintf(w, "%s{key=%q} %d\n", s.name, r.label, s.get(r))
		}
	}
}
