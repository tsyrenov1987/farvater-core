package wire

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/tsyrenov1987/farvater-core/kilvater"
)

type kilWire struct {
	spec PathSpec
	key  kilvater.Key
	mux  *h2Mux
}

func newKilvater(s PathSpec) (Wire, error) {
	k, err := kilvater.ParseKey(s.Key)
	if err != nil {
		return nil, err
	}
	w := &kilWire{spec: s, key: k}
	w.mux = newH2Mux(func(ctx context.Context) (net.Conn, error) {
		return dialSecure(ctx, s, false)
	}, 15*time.Second, 5*time.Second)
	return w, nil
}

func (w *kilWire) ID() string     { return w.spec.ID }
func (w *kilWire) Spec() PathSpec { return w.spec }

// NeedsHandshake: a connection the readLoop dropped (freeze, GOAWAY) is still
// held until the next openStream replaces it; the next Dial over it
// handshakes, so the governor must count it as one (h2Mux.needsDial).
func (w *kilWire) NeedsHandshake() bool { return w.mux.needsDial() }

func (w *kilWire) Close() error        { return w.mux.Close() }
func (w *kilWire) Refresh(t time.Time) { w.mux.refresh(t) }

func (w *kilWire) Dial(ctx context.Context) (Session, error) {
	path := w.spec.Path
	if path == "" {
		path = "/connect"
	}
	tag := kilvater.NewTag(w.key, path, time.Now())
	host := w.spec.HostHeader
	if host == "" {
		host = w.spec.ServerSNI()
	}
	u := &url.URL{Scheme: "https", Host: host, Path: path}
	h := http.Header{}
	h.Set("Cookie", kilvater.CookieName+"="+tag)
	browserHeaders(h, "fetch")
	st, err := w.mux.openStream(ctx, http.MethodPost, u.String(), h)
	if err != nil {
		return nil, err
	}
	return &kilSession{conn: st}, nil
}

type kilSession struct{ conn net.Conn }

func (s *kilSession) Close() error { return s.conn.Close() }

func (s *kilSession) Run(ctx context.Context, target Target, prelude []byte, up <-chan []byte, down io.Writer, m Meter) (Outcome, error) {
	body := []byte{kilvater.NetTCP}
	body, err := kilvater.AppendAddr(body, target.String())
	if err != nil {
		s.conn.Close()
		return OutcomeError, err
	}
	if err := kilvater.WriteFrame(s.conn, kilvater.FrameOpen, body); err != nil {
		s.conn.Close()
		return OutcomeError, err
	}
	// Vary the size of the first record we put on the wire.
	if err := kilvater.WritePad(s.conn); err != nil {
		s.conn.Close()
		return OutcomeError, err
	}
	if len(prelude) > 0 {
		if err := writeDataFrames(s.conn, prelude); err != nil {
			s.conn.Close()
			return OutcomeError, err
		}
	}
	return runStream(ctx, s.conn, &kilFrameWriter{w: s.conn}, &kilFrameReader{r: s.conn}, up, down, m)
}

func writeDataFrames(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n := len(p)
		if n > kilvater.MaxFrame {
			n = kilvater.MaxFrame
		}
		if err := kilvater.WriteFrame(w, kilvater.FrameData, p[:n]); err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

type kilFrameWriter struct{ w io.Writer }

func (fw *kilFrameWriter) Write(p []byte) (int, error) {
	return len(p), writeDataFrames(fw.w, p)
}

type kilFrameReader struct {
	r   io.Reader
	buf []byte
	rem []byte
}

func (fr *kilFrameReader) Read(p []byte) (int, error) {
	for len(fr.rem) == 0 {
		typ, body, err := kilvater.ReadFrame(fr.r, fr.buf)
		if err != nil {
			return 0, err
		}
		fr.buf = body[:0]
		switch typ {
		case kilvater.FrameData:
			fr.rem = body
		case kilvater.FramePad:
			continue
		case kilvater.FrameClose:
			return 0, io.EOF
		default:
			return 0, fmt.Errorf("kilvater: unexpected frame type %d", typ)
		}
	}
	n := copy(p, fr.rem)
	fr.rem = fr.rem[n:]
	return n, nil
}
