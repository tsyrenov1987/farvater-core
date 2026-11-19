package kilvater

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

func TestSealRoundTrip(t *testing.T) {
	var k Key
	rand.Read(k[:])
	sid := []byte("0123456789abcdef")
	msg := make([]byte, 100<<10) // several records
	rand.Read(msg)
	var wire bytes.Buffer
	w := NewSealWriter(&wire, k, sid, SealUp)
	w.Write(msg[:10])
	w.Write(msg[10:])
	if bytes.Contains(wire.Bytes(), msg[20:60]) {
		t.Fatal("plaintext shows on the wire")
	}
	got, err := io.ReadAll(NewSealReader(bytes.NewReader(wire.Bytes()), k, sid, SealUp))
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("round trip: %d bytes, %v", len(got), err)
	}
	// The other direction, another sid, or a flipped bit do not open.
	for name, r := range map[string]*SealReader{
		"direction": NewSealReader(bytes.NewReader(wire.Bytes()), k, sid, SealDown),
		"sid":       NewSealReader(bytes.NewReader(wire.Bytes()), k, []byte("fedcba9876543210"), SealUp),
	} {
		if _, err := r.Read(make([]byte, 10)); !errors.Is(err, ErrSealOpen) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	b := bytes.Clone(wire.Bytes())
	b[5] ^= 1
	if _, err := NewSealReader(bytes.NewReader(b), k, sid, SealUp).Read(make([]byte, 10)); !errors.Is(err, ErrSealOpen) {
		t.Fatalf("tampered: %v", err)
	}
}

func TestSplitPath(t *testing.T) {
	sid := "AAAAAAAAAAAAAAAAAAAAAA"
	for p, want := range map[string]splitKind{
		"/connect/" + sid + "/d":   splitDown,
		"/connect/" + sid + "/u/7": splitUp,
		"/connect":                 splitNone,
		"/connect/" + sid + "/u/x": splitNone,
		"/connect/short/d":         splitNone,
		// ext=ts on the link (CDN Timeweb wants a file): the extension is not part of the kind
		"/content/media/live/" + sid + "/d.ts":   splitDown,
		"/content/media/live/" + sid + "/u/7.ts": splitUp,
		"/connect/" + sid + "/u/7.TS":            splitNone,
		"/connect/" + sid + "/d.toolong":         splitNone,
	} {
		if k, _, _ := parseSplitPath(p); k != want {
			t.Fatalf("%s: %v, want %v", p, k, want)
		}
	}
}

// Pieces that arrive out of order go to the tunnel in order, and the end mark
// on the last one ends the stream after everything before it.
func TestSplitPutOrder(t *testing.T) {
	pr, pw := io.Pipe()
	s := &splitSess{pend: map[uint64][]byte{}, finAt: -1, pr: pr, pw: pw}
	done := make(chan []byte)
	go func() { b, _ := io.ReadAll(pr); done <- b }()
	if err := s.put(2, []byte("c"), true); err != nil {
		t.Fatal(err)
	}
	s.put(1, []byte("b"), false)
	s.put(1, []byte("X"), false) // a repeat is dropped
	s.put(0, []byte("a"), false)
	if got := string(<-done); got != "abc" {
		t.Fatalf("got %q", got)
	}
}
