package kilvater

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"
)

// syncBuf is a bytes.Buffer safe for the idle-PAD goroutine and the test to
// touch at once.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.b.Bytes()...)
}

// drainFrames reads every whole frame a shaper wrote, the way a peer does:
// DATA bodies are joined, PAD is counted and skipped.
func drainFrames(t *testing.T, raw []byte) (dataSizes []int, pads int, payload []byte) {
	t.Helper()
	r := bytes.NewReader(raw)
	var buf []byte
	for {
		typ, body, err := ReadFrame(r, buf)
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		switch typ {
		case FrameData:
			dataSizes = append(dataSizes, len(body))
			payload = append(payload, body...)
		case FramePad:
			pads++
		default:
			t.Fatalf("unexpected frame type %d", typ)
		}
		buf = body[:0]
	}
}

// PadOff must frame exactly as v1 did: 16 KiB DATA chunks, nothing else. This
// pins the compatibility floor so a node (or link) set to off is byte-for-byte
// the old behaviour.
func TestShaperOffMatchesLegacyFraming(t *testing.T) {
	var buf bytes.Buffer
	sh := NewShaper(&buf, PadOff)
	defer sh.Close()
	payload := bytes.Repeat([]byte("x"), 5*MaxFrame+100)
	if err := sh.WriteData(payload); err != nil {
		t.Fatal(err)
	}
	sizes, pads, got := drainFrames(t, buf.Bytes())
	if pads != 0 {
		t.Errorf("off mode wrote %d PAD frames, want 0", pads)
	}
	want := []int{MaxFrame, MaxFrame, MaxFrame, MaxFrame, MaxFrame, 100}
	if len(sizes) != len(want) {
		t.Fatalf("DATA frame sizes %v, want %v", sizes, want)
	}
	for i := range want {
		if sizes[i] != want[i] {
			t.Fatalf("DATA frame sizes %v, want %v", sizes, want)
		}
	}
	if !bytes.Equal(got, payload) {
		t.Error("off mode did not reassemble to the original payload")
	}
}

// Moderate must break the single spike of 16 KiB records a bulk transfer is
// into a spread of sizes. This is the point of the item: RED on v1 framing
// (every frame is MaxFrame), GREEN here.
func TestShaperModerateVariesRecordSizes(t *testing.T) {
	var buf bytes.Buffer
	sh := NewShaper(&buf, PadModerate)
	defer sh.Close()
	payload := bytes.Repeat([]byte("y"), 2<<20) // 2 MiB
	if err := sh.WriteData(payload); err != nil {
		t.Fatal(err)
	}
	sizes, _, got := drainFrames(t, buf.Bytes())
	if !bytes.Equal(got, payload) {
		t.Fatal("moderate did not reassemble to the original payload")
	}
	if len(sizes) < 50 {
		t.Fatalf("only %d DATA frames; too few to judge the spread", len(sizes))
	}

	var atMax, small, medium, large int
	for _, n := range sizes {
		if n == MaxFrame {
			atMax++
		}
		switch {
		case n < 512:
			small++
		case n < 8000:
			medium++
		default:
			large++
		}
	}
	// v1 framing makes all-but-the-last frame exactly MaxFrame.
	if frac := float64(atMax) / float64(len(sizes)); frac > 0.5 {
		t.Errorf("%.0f%% of DATA frames are the maximum size; the bulk spike is not broken", frac*100)
	}
	if small == 0 || medium == 0 || large == 0 {
		t.Errorf("record-size buckets not all populated: small=%d medium=%d large=%d", small, medium, large)
	}
}

// Every mode's output must read back as the exact bytes written, with PAD
// transparent: this is the v1-compatibility guarantee.
func TestShaperReassemblesEveryMode(t *testing.T) {
	payload := bytes.Repeat([]byte("abcdefgh"), 200000) // 1.6 MiB, not frame-aligned
	for _, mode := range []PadMode{PadOff, PadModerate, PadHeavy} {
		var buf syncBuf
		sh := newShaper(&buf, mode, time.Hour) // long idle: no idle PAD interferes
		if err := sh.WriteData(payload); err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		sh.Close()
		_, _, got := drainFrames(t, buf.Bytes())
		if !bytes.Equal(got, payload) {
			t.Errorf("%s: reassembled payload differs from original (%d vs %d bytes)", mode, len(got), len(payload))
		}
	}
}

// Heavy must put a PAD on an idle connection so a silence is not plainly idle.
func TestShaperHeavyIdlePad(t *testing.T) {
	var buf syncBuf
	sh := newShaper(&buf, PadHeavy, 15*time.Millisecond)
	time.Sleep(120 * time.Millisecond) // several intervals of silence
	sh.Close()
	_, pads, _ := drainFrames(t, buf.Bytes())
	if pads == 0 {
		t.Fatal("heavy mode sent no PAD during a silence")
	}
}

// Moderate starts no goroutine and so sends nothing while idle.
func TestShaperModerateDoesNotPadIdle(t *testing.T) {
	var buf syncBuf
	sh := newShaper(&buf, PadModerate, 15*time.Millisecond)
	time.Sleep(80 * time.Millisecond)
	sh.Close()
	if n := len(buf.Bytes()); n != 0 {
		t.Fatalf("moderate wrote %d bytes while idle, want 0", n)
	}
}

func TestParsePadMode(t *testing.T) {
	cases := map[string]PadMode{
		"":         PadModerate,
		"moderate": PadModerate,
		"unknown":  PadModerate,
		"off":      PadOff,
		"OFF":      PadOff,
		" heavy ":  PadHeavy,
		"max":      PadHeavy,
	}
	for in, want := range cases {
		if got := ParsePadMode(in); got != want {
			t.Errorf("ParsePadMode(%q) = %v, want %v", in, got, want)
		}
	}
}
