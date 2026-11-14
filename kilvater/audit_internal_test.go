package kilvater

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
)

// The server's own and its sister nodes' addresses answer the tunnel only on
// the public web ports; a mail port is closed everywhere.
func TestAllowedDenyDstAndPorts(t *testing.T) {
	s := &Server{
		DenyDst:   []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32"), netip.MustParsePrefix("198.51.100.0/24")},
		SelfPorts: []uint16{80, 443},
		DenyPorts: []uint16{25},
	}
	for addr, want := range map[string]bool{
		"203.0.113.7:443":         true,
		"203.0.113.7:80":          true,
		"203.0.113.7:9100":        false,
		"203.0.113.7:22":          false,
		"[::ffff:203.0.113.7]:22": false,
		"198.51.100.9:2083":       false,
		"198.51.100.9:443":        true,
		"203.0.113.8:9100":        true, // not ours
		"1.1.1.1:25":              false,
		"1.1.1.1:587":             true,
		"127.0.0.1:443":           false,
	} {
		if got := s.allowed(netip.MustParseAddrPort(addr)); got != want {
			t.Errorf("allowed(%s) = %v, want %v", addr, got, want)
		}
	}
	// AllowPrivate opens private space, not the denied list.
	s.AllowPrivate = true
	if !s.allowed(netip.MustParseAddrPort("127.0.0.1:443")) || s.allowed(netip.MustParseAddrPort("203.0.113.7:22")) {
		t.Error("AllowPrivate must open loopback and leave DenyDst closed")
	}
}

// A denied own address is refused with CLOSE(2) and never dialed.
func TestTCPRefusesOwnAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	s := &Server{AllowPrivate: true, DenyDst: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, SelfPorts: []uint16{443}}
	var down bytes.Buffer
	upR, upW := io.Pipe()
	upW.Close()
	s.tcp(context.Background(), ln.Addr().String(), upR, &down, nil)
	typ, body, err := ReadFrame(&down, nil)
	if err != nil || typ != FrameClose || len(body) != 1 || body[0] != CloseForbidden {
		t.Fatalf("want CLOSE(2), got type=%d body=%v err=%v", typ, body, err)
	}
}

// recWriter keeps each Write apart, as TLS keeps each in a record of its own.
type recWriter struct{ recs [][]byte }

func (w *recWriter) Write(p []byte) (int, error) {
	w.recs = append(w.recs, append([]byte(nil), p...))
	return len(p), nil
}

// A stream's first small writes each go out as one record of DATA and PAD
// whose size no longer follows the payload's; later writes are plain.
func TestShaperEarlyWritesArePadded(t *testing.T) {
	var w recWriter
	s := NewShaper(&w, PadModerate)
	defer s.Close()
	var want []byte
	for i := 0; i < earlyWrites+4; i++ {
		p := bytes.Repeat([]byte{byte(i)}, 37+i)
		want = append(want, p...)
		if err := s.WriteData(p); err != nil {
			t.Fatal(err)
		}
	}
	if len(w.recs) != earlyWrites+4 {
		t.Fatalf("%d records, want one per small write (%d)", len(w.recs), earlyWrites+4)
	}
	var all []byte
	for i, r := range w.recs {
		all = append(all, r...)
		if i < earlyWrites {
			if len(r) < earlyFloor || len(r) > earlyFloor+500+8 {
				t.Errorf("early record %d is %d bytes, want %d–%d", i, len(r), earlyFloor, earlyFloor+508)
			}
		} else if len(r) != 4+37+i {
			t.Errorf("record %d is %d bytes, want a bare DATA frame of %d", i, len(r), 4+37+i)
		}
	}
	_, pads, got := drainFrames(t, all)
	if !bytes.Equal(got, want) {
		t.Fatal("payload changed by early padding")
	}
	if pads != earlyWrites {
		t.Errorf("%d PAD frames, want %d", pads, earlyWrites)
	}
}

func TestShaperOffSendsNoEarlyPad(t *testing.T) {
	var w recWriter
	s := NewShaper(&w, PadOff)
	if err := s.WriteData([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if len(w.recs) != 1 || len(w.recs[0]) != 4+5 {
		t.Fatalf("PadOff wrote %v, want one bare DATA frame", w.recs)
	}
}

// OPEN, the app's first bytes and a PAD leave as one record.
func TestShaperWriteOpeningIsOneRecord(t *testing.T) {
	var w recWriter
	s := NewShaper(&w, PadModerate)
	defer s.Close()
	open := AppendFrame(nil, FrameOpen, []byte{NetTCP, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', ':', '4', '4', '3'})
	if err := s.WriteOpening(open, []byte("client hello")); err != nil {
		t.Fatal(err)
	}
	if len(w.recs) != 1 {
		t.Fatalf("%d records, want 1", len(w.recs))
	}
	r := bytes.NewReader(w.recs[0])
	var types []byte
	for {
		typ, _, err := ReadFrame(r, nil)
		if err != nil {
			break
		}
		types = append(types, typ)
	}
	if !bytes.Equal(types, []byte{FrameOpen, FrameData, FramePad}) {
		t.Fatalf("frames %v, want OPEN, DATA, PAD", types)
	}
	if len(w.recs[0]) < earlyFloor {
		t.Errorf("opening record is %d bytes, want at least %d", len(w.recs[0]), earlyFloor)
	}
}

// A frame type this build does not know is skipped, not a protocol error.
func TestTCPSkipsUnknownFrameTypes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		b, _ := io.ReadAll(c)
		c.Close()
		got <- b
	}()
	var up bytes.Buffer
	WriteFrame(&up, 9, []byte("from the future"))
	WriteFrame(&up, FrameData, []byte("payload"))
	WriteFrame(&up, FrameClose, []byte{0})
	var down bytes.Buffer
	(&Server{AllowPrivate: true}).tcp(context.Background(), ln.Addr().String(), &up, &down, nil)
	if b := <-got; string(b) != "payload" {
		t.Fatalf("target got %q, want %q", b, "payload")
	}
}
