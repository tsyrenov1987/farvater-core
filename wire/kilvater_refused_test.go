package wire

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/kilvater"
)

// A target the node cannot reach ends the flow as the remote's close, with
// ErrTargetUnreachable beside it, so the caller does not blame the path.
func TestKilvaterTargetUnreachable(t *testing.T) {
	// A port nothing listens on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	var p int
	for _, c := range port {
		p = p*10 + int(c-'0')
	}

	key, hexKey := kilTestKey(t)
	w, err := newKilWire(kilTestSpec(hexKey), kilServerDial(t, key))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := w.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	up := make(chan []byte)
	var down bytes.Buffer
	out, err := sess.Run(ctx, Target{Host: "127.0.0.1", Port: p}, []byte("hello"), up, &down, nopMeter{})
	if out != OutcomeRemoteFin || !errors.Is(err, ErrTargetUnreachable) {
		t.Fatalf("got %v, %v; want OutcomeRemoteFin, ErrTargetUnreachable", out, err)
	}
}

// The same from a server that predates CLOSE codes' meaning nothing changes:
// a clean end stays a clean end.
func TestKilFrameReaderCloseCodes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		frames  func(b *bytes.Buffer)
		refused bool
	}{
		{"fail before data", func(b *bytes.Buffer) { kilvater.WriteFrame(b, kilvater.FrameClose, []byte{kilvater.CloseDialFail}) }, true},
		{"forbidden", func(b *bytes.Buffer) { kilvater.WriteFrame(b, kilvater.FrameClose, []byte{kilvater.CloseForbidden}) }, true},
		{"clean", func(b *bytes.Buffer) { kilvater.WriteFrame(b, kilvater.FrameClose, []byte{kilvater.CloseOK}) }, false},
		{"no code", func(b *bytes.Buffer) { kilvater.WriteFrame(b, kilvater.FrameClose, nil) }, false},
		{"after data", func(b *bytes.Buffer) {
			kilvater.WriteFrame(b, kilvater.FrameData, []byte("x"))
			kilvater.WriteFrame(b, kilvater.FrameClose, []byte{kilvater.CloseDialFail})
		}, false},
		{"unknown frame skipped", func(b *bytes.Buffer) {
			kilvater.WriteFrame(b, 9, []byte("future"))
			kilvater.WriteFrame(b, kilvater.FrameClose, []byte{kilvater.CloseDialFail})
		}, true},
	} {
		var b bytes.Buffer
		tc.frames(&b)
		fr := &kilFrameReader{r: &b}
		p := make([]byte, 16)
		for {
			if _, err := fr.Read(p); err != nil {
				break
			}
		}
		if fr.refused != tc.refused {
			t.Errorf("%s: refused = %v, want %v", tc.name, fr.refused, tc.refused)
		}
	}
}

// A node that does not know the key answers with its site, and the caller is
// told the key was refused rather than left with a bare HTTP status.
func TestKilvaterAccessRefused(t *testing.T) {
	_, hexKey := kilTestKey(t)
	other, _ := kilTestKey(t)
	w, err := newKilWire(kilTestSpec(hexKey), kilServerDial(t, other))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := w.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	up := make(chan []byte)
	var down bytes.Buffer
	_, err = sess.Run(ctx, Target{Host: "127.0.0.1", Port: 9}, []byte("hello"), up, &down, nopMeter{})
	if !errors.Is(err, ErrAccessRefused) {
		t.Fatalf("got %v; want ErrAccessRefused", err)
	}
	if errors.Is(err, ErrTargetUnreachable) {
		t.Fatal("a refused key is not an unreachable target")
	}
}
