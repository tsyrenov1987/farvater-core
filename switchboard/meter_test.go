package switchboard

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/wire"
)

// record is one TLS application-data record with an n-byte body.
func record(n int) []byte {
	return append([]byte{23, 3, 3, byte(n >> 8), byte(n)}, bytes.Repeat([]byte{0xAB}, n)...)
}

func newMeter() *meter {
	return &meter{f: &flow{s: &Switchboard{cfg: DefaultConfig()}}}
}

func TestTLSTrackFollowsRecords(t *testing.T) {
	var tr tlsTrack
	r := record(100)
	tr.feed(r[:3]) // header split across chunks
	if !tr.midRecord() {
		t.Fatal("partial header must count as mid-record")
	}
	tr.feed(r[3:55])
	if !tr.midRecord() {
		t.Fatal("partial body must count as mid-record")
	}
	tr.feed(r[55:])
	if tr.midRecord() {
		t.Fatal("complete record must be a boundary")
	}
	tr.feed(append(record(16384), record(7)...))
	if tr.midRecord() || tr.off {
		t.Fatal("two whole records in one chunk must end on a boundary")
	}

	var plain tlsTrack
	plain.feed([]byte("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n"))
	if !plain.off || plain.midRecord() {
		t.Fatal("a non-TLS stream must switch tracking off")
	}
}

// A completed 1 MiB response followed by keep-alive silence is not a stall.
func TestQuietAfterCompleteResponseIsNotAStall(t *testing.T) {
	m := newMeter()
	m.Up(record(300)) // request
	for i := 0; i < 64; i++ {
		m.Down(record(16384))
	}
	m.tick(nowMs()+10_000, 4000)
	if s := m.snap(); s.stalls != 0 || s.inStall {
		t.Fatalf("idle after a complete response counted as stall: %+v", s)
	}
}

// HTTP/2 sends WINDOW_UPDATE and SETTINGS ACK after the data; no answer is
// owed, so the silence that follows is not a stall.
func TestControlFrameAfterResponseIsNotAStall(t *testing.T) {
	m := newMeter()
	m.Up(record(300))
	m.Down(record(5000))
	m.Up(record(30)) // e.g. WINDOW_UPDATE
	m.tick(nowMs()+10_000, 4000)
	if s := m.snap(); s.stalls != 0 {
		t.Fatalf("control frame after a response counted as stall: %+v", s)
	}
}

// Silence in the middle of a record means bytes are missing: a stall, which
// clears when the bytes arrive.
func TestQuietMidRecordIsAStall(t *testing.T) {
	m := newMeter()
	m.Up(record(300))
	r := record(16384)
	m.Down(record(4000))
	m.Down(r[:9000])
	m.tick(nowMs()+5_000, 4000)
	if s := m.snap(); s.stalls != 1 || !s.inStall {
		t.Fatalf("quiet inside a record must be a stall: %+v", s)
	}
	m.Down(r[9000:])
	if m.snap().inStall {
		t.Fatal("arrival of the missing bytes must clear the stall")
	}
}

func TestNonTLSGetsNoStallVerdictAfterAnswer(t *testing.T) {
	m := newMeter()
	m.Up([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	m.Down([]byte("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\nabc"))
	m.tick(nowMs()+10_000, 4000)
	if s := m.snap(); s.stalls != 0 {
		t.Fatalf("non-TLS flow got a stall verdict: %+v", s)
	}
}

// silent is a session whose remote never answers.
type silent struct{}

func (silent) Run(ctx context.Context, _ wire.Target, _ []byte, _ <-chan []byte, _ io.Writer, _ wire.Meter) (wire.Outcome, error) {
	<-ctx.Done()
	return wire.OutcomeCanceled, ctx.Err()
}
func (silent) Close() error { return nil }

// The first-byte clock starts when the app sends: an unused connection is not
// timed out, and one that asked and got nothing is.
func TestFirstByteClockStartsWithTheApp(t *testing.T) {
	f := &flow{s: &Switchboard{cfg: DefaultConfig()}, fbDeadlineMs: 300, up: make(chan []byte)}
	a := f.newAttempt("p", false)
	type result struct{ fbTimeout bool }
	done := make(chan result, 1)
	go func() {
		_, _, fbTimeout, _ := f.run(context.Background(), silent{}, a, nil)
		done <- result{fbTimeout}
	}()
	select {
	case <-done:
		t.Fatal("a connection the app has not used was timed out")
	case <-time.After(900 * time.Millisecond):
	}
	a.m.Up(record(300)) // the app asks
	select {
	case r := <-done:
		if !r.fbTimeout {
			t.Fatal("run ended without a first-byte timeout")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no first-byte timeout after the app asked and got nothing")
	}
}
