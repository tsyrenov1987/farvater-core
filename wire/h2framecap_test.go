package wire

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"runtime"
	"testing"

	"golang.org/x/net/http2"
)

// trickleConn hands out what it holds a few bytes per Read, so a frame header
// or a setting falls across reads at every offset.
type trickleConn struct {
	net.Conn
	r    io.Reader
	step int
}

func (c *trickleConn) Read(p []byte) (int, error) { return c.r.Read(p[:min(len(p), c.step)]) }

// TestH2FrameCapHidesTheServersFrameSize: SETTINGS_MAX_FRAME_SIZE is gone from
// the server's SETTINGS whatever the read boundaries, the other settings and
// the frames after it pass untouched, a DATA payload that looks like the
// setting included.
func TestH2FrameCapHidesTheServersFrameSize(t *testing.T) {
	var srv bytes.Buffer
	fr := http2.NewFramer(&srv, nil)
	fr.WriteSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100},
		http2.Setting{ID: http2.SettingMaxFrameSize, Val: 1 << 20},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
	look := []byte{0, 5, 0, 0x10, 0, 0} // a MAX_FRAME_SIZE setting, inside a DATA frame
	fr.WriteData(1, false, look)
	fr.WriteSettingsAck()
	fr.WriteSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: 1 << 14 * 4})
	for step := 1; step <= srv.Len(); step++ {
		c := &h2FrameCap{Conn: &trickleConn{r: bytes.NewReader(srv.Bytes()), step: step}}
		rd := http2.NewFramer(nil, c)
		f, err := rd.ReadFrame()
		if err != nil {
			t.Fatalf("step %d: settings: %v", step, err)
		}
		sf := f.(*http2.SettingsFrame)
		if v, ok := sf.Value(http2.SettingMaxFrameSize); ok {
			t.Fatalf("step %d: the Transport still sees MAX_FRAME_SIZE %d", step, v)
		}
		if v, _ := sf.Value(http2.SettingMaxConcurrentStreams); v != 100 {
			t.Fatalf("step %d: MAX_CONCURRENT_STREAMS %d, want 100", step, v)
		}
		if v, _ := sf.Value(http2.SettingInitialWindowSize); v != 1<<20 {
			t.Fatalf("step %d: INITIAL_WINDOW_SIZE %d, want %d", step, v, 1<<20)
		}
		f, err = rd.ReadFrame()
		if err != nil {
			t.Fatalf("step %d: data: %v", step, err)
		}
		if d := f.(*http2.DataFrame).Data(); !bytes.Equal(d, look) {
			t.Fatalf("step %d: DATA payload changed to %x", step, d)
		}
		if f, err = rd.ReadFrame(); err != nil || !f.(*http2.SettingsFrame).IsAck() {
			t.Fatalf("step %d: want the SETTINGS ack, got %v %v", step, f, err)
		}
		if f, err = rd.ReadFrame(); err != nil {
			t.Fatalf("step %d: later settings: %v", step, err)
		}
		if v, ok := f.(*http2.SettingsFrame).Value(http2.SettingMaxFrameSize); ok {
			t.Fatalf("step %d: a later SETTINGS still names MAX_FRAME_SIZE %d", step, v)
		}
	}
}

// TestH2MuxIdleStreamsHoldLittleBehindLargeFrames: a stream whose upload has
// gone quiet holds next to nothing, however large a frame the server allows.
// Go's Transport reads a request body through a scratch buffer as long as the
// server's frame, up to 512 KiB, for the stream's whole life; behind Xray's
// 1 MiB frames 64 quiet streams held 32 MiB of it.
func TestH2MuxIdleStreamsHoldLittleBehindLargeFrames(t *testing.T) {
	dial := func(ctx context.Context) (net.Conn, error) {
		c, s := net.Pipe()
		go (&http2.Server{MaxReadFrameSize: 1 << 20}).ServeConn(s, &http2.ServeConnOpts{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				buf := make([]byte, 64)
				for {
					n, err := r.Body.Read(buf)
					if n > 0 {
						w.Write(buf[:n])
						w.(http.Flusher).Flush()
					}
					if err != nil {
						return
					}
				}
			}),
		})
		return c, nil
	}
	m := newH2Mux(dial, 0, 0)
	defer m.Close()
	heap := func() uint64 {
		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		return ms.HeapAlloc
	}
	before := heap()
	const n = 64
	for i := 0; i < n; i++ {
		s := openOrFail(t, m)
		defer s.Close()
		echo(t, s, "x") // the upload is under way, then goes quiet
	}
	held := int64(heap()) - int64(before)
	// Both ends live in this process; at 512 KiB a stream they held over 32 MiB.
	if limit := int64(n * 96 << 10); held > limit {
		t.Fatalf("%d quiet streams hold %d KiB, want at most %d KiB", n, held>>10, limit>>10)
	}
	t.Logf("%d quiet streams hold %d KiB", n, held>>10)
}
