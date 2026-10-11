package wire

import (
	"bytes"
	"context"
	"io"
	"math/rand/v2"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// shaperConn records what the shaper writes, one entry per write, and hands
// it the server's bytes queued in in.
type shaperConn struct {
	net.Conn
	writes [][]byte
	in     bytes.Buffer
}

func (c *shaperConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (c *shaperConn) Read(p []byte) (int, error) { return c.in.Read(p) }

func (c *shaperConn) all() []byte { return bytes.Join(c.writes, nil) }

// goClient writes what the http2 Transport would: its framer and its HPACK
// encoder, in the Transport's order.
type goClient struct {
	buf  bytes.Buffer
	fr   *http2.Framer
	hbuf bytes.Buffer
	enc  *hpack.Encoder
}

func newGoClient() *goClient {
	c := &goClient{}
	c.fr = http2.NewFramer(&c.buf, nil)
	c.enc = hpack.NewEncoder(&c.hbuf)
	return c
}

func (c *goClient) take() []byte {
	b := append([]byte(nil), c.buf.Bytes()...)
	c.buf.Reset()
	return b
}

// open writes the preface and the Transport's SETTINGS and window, as
// chromeH2.transport configures it.
func (c *goClient) open() []byte {
	c.buf.WriteString(http2.ClientPreface)
	c.fr.WriteSettings(
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 6291456},
		http2.Setting{ID: http2.SettingMaxFrameSize, Val: 16384},
		http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: 262144},
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 65536})
	c.fr.WriteWindowUpdate(0, 15663105)
	return c.take()
}

// request writes one request's HEADERS (and CONTINUATION past maxFrag).
func (c *goClient) request(id uint32, end bool, maxFrag int, fields ...string) []byte {
	c.hbuf.Reset()
	for i := 0; i+1 < len(fields); i += 2 {
		c.enc.WriteField(hpack.HeaderField{Name: fields[i], Value: fields[i+1]})
	}
	blk := c.hbuf.Bytes()
	first := min(len(blk), maxFrag)
	c.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: blk[:first], EndStream: end, EndHeaders: first == len(blk)})
	for blk = blk[first:]; len(blk) > 0; {
		n := min(len(blk), maxFrag)
		c.fr.WriteContinuation(id, n == len(blk), blk[:n])
		blk = blk[n:]
	}
	return c.take()
}

func goRequest(method, path, prio string, extra ...string) []string {
	f := []string{":authority", "kv.test", ":method", method, ":path", path, ":scheme", "https"}
	f = append(f, extra...)
	return append(f, "priority", prio)
}

// readShaped parses what the shaper wrote, as the server reads it.
func readShaped(t *testing.T, b []byte) []http2.Frame {
	t.Helper()
	if !bytes.HasPrefix(b, []byte(http2.ClientPreface)) {
		t.Fatal("no preface first")
	}
	fr := http2.NewFramer(nil, bytes.NewReader(b[len(http2.ClientPreface):]))
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	var out []http2.Frame
	for {
		f, err := fr.ReadFrame()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		switch f := f.(type) {
		case *http2.MetaHeadersFrame:
			cp := *f
			cp.Fields = append([]hpack.HeaderField(nil), f.Fields...)
			out = append(out, &cp)
		case *http2.DataFrame:
			out = append(out, &dataCopy{id: f.StreamID, data: append([]byte(nil), f.Data()...), end: f.StreamEnded()})
		default:
			out = append(out, f)
		}
	}
}

type dataCopy struct {
	http2.Frame
	id   uint32
	data []byte
	end  bool
}

// serverEnds queues the server's END_STREAM on id and lets the shaper read it.
func serverEnds(t *testing.T, s *h2Shaper, c *shaperConn, ids ...uint32) {
	t.Helper()
	fr := http2.NewFramer(&c.in, nil)
	for _, id := range ids {
		fr.WriteData(id, true, nil)
	}
	io.Copy(io.Discard, s)
}

// The priorities Chrome gave streams 1–9 in testdata/h2fp, replayed: a page,
// then a stylesheet, a script and an image while the stylesheet is open, then
// a POST once all have finished.
func TestH2ShaperChromePriorities(t *testing.T) {
	ref := loadH2FP(t, "testdata/h2fp/chrome-154.json")
	want := map[uint32]h2fpPriority{}
	for _, f := range ref.Frames {
		if f.Type == "HEADERS" && f.Priority != nil {
			want[f.Stream] = *f.Priority
		}
	}
	c := &shaperConn{}
	s := newH2Shaper(c, chromeH2)
	g := newGoClient()
	write := func(b []byte) {
		if _, err := s.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	write(g.open())
	write(g.request(1, true, 16384, goRequest("GET", "/", "u=0, i", "sec-fetch-mode", "navigate")...))
	serverEnds(t, s, c, 1)
	write(g.request(3, true, 16384, goRequest("GET", "/s.css", "u=0")...))
	write(g.request(5, true, 16384, goRequest("GET", "/a.js", "u=1")...))
	write(g.request(7, true, 16384, goRequest("GET", "/i.png", "u=2, i")...))
	serverEnds(t, s, c, 3, 5, 7)
	write(g.request(9, false, 16384, goRequest("POST", "/connect", "u=1, i")...))

	for _, f := range readShaped(t, c.all()) {
		h, ok := f.(*http2.MetaHeadersFrame)
		if !ok {
			continue
		}
		p := h.Priority
		got := h2fpPriority{p.Exclusive, p.StreamDep, int(p.Weight) + 1}
		if w, ok := want[h.StreamID]; !ok || !h.HasPriority() || got != w {
			t.Errorf("stream %d: priority %+v, want %+v as Chrome", h.StreamID, got, w)
		}
	}
}

// What the Transport writes in pieces (a frame split over two flushes of its
// buffered writer) comes out as it would whole, and a header block on
// CONTINUATION frames is gathered and written again in full.
func TestH2ShaperSplitWritesAndContinuation(t *testing.T) {
	g := newGoClient()
	var parts [][]byte
	parts = append(parts, g.open())
	big := strings.Repeat("x", 40000)
	parts = append(parts, g.request(1, false, 16384, goRequest("POST", "/connect", "u=1, i", "cookie", big, "user-agent", "UA")...))
	g.fr.WriteData(1, false, bytes.Repeat([]byte{7}, 16384))
	g.fr.WritePing(false, [8]byte{1})
	g.fr.WriteData(1, true, []byte("end"))
	parts = append(parts, g.take())
	parts = append(parts, g.request(3, true, 100, goRequest("GET", "/a.js", "u=1", "user-agent", "UA")...))
	stream := bytes.Join(parts, nil)

	whole := &shaperConn{}
	ws := newH2Shaper(whole, chromeH2)
	for _, p := range parts {
		ws.Write(p)
	}
	pieces := &shaperConn{}
	ps := newH2Shaper(pieces, chromeH2)
	r := rand.New(rand.NewPCG(1, 2))
	for b := stream; len(b) > 0; {
		n := min(len(b), 1+r.IntN(700))
		if k, err := ps.Write(b[:n]); err != nil || k != n {
			t.Fatalf("Write = %d, %v", k, err)
		}
		b = b[n:]
	}
	if !bytes.Equal(whole.all(), pieces.all()) {
		t.Fatal("written in pieces, the shaper's output differs from the whole")
	}
	for i, w := range pieces.writes {
		if i == 0 {
			w = w[len(http2.ClientPreface):]
		}
		for len(w) > 0 {
			n := 9 + (int(w[0])<<16 | int(w[1])<<8 | int(w[2]))
			if n > len(w) {
				t.Fatalf("write %d ends inside a frame", i)
			}
			w = w[n:]
		}
	}
	frames := readShaped(t, whole.all())
	var heads []*http2.MetaHeadersFrame
	var data []byte
	for _, f := range frames {
		switch f := f.(type) {
		case *http2.MetaHeadersFrame:
			heads = append(heads, f)
		case *dataCopy:
			data = append(data, f.data...)
		}
	}
	if len(heads) != 2 {
		t.Fatalf("%d requests, want 2", len(heads))
	}
	if v := heads[0].Fields; v[0].Name != ":method" || heads[0].PseudoValue("path") != "/connect" {
		t.Fatalf("first request %v", v[:4])
	}
	var cookie string
	for _, f := range heads[0].Fields {
		if f.Name == "cookie" {
			cookie = f.Value
		}
	}
	if cookie != big || len(data) != 16384+3 || heads[1].PseudoValue("path") != "/a.js" || !heads[1].StreamEnded() {
		t.Fatalf("content changed: cookie %d bytes, data %d bytes, second %q", len(cookie), len(data), heads[1].PseudoValue("path"))
	}
}

// A server that keeps a smaller HPACK table than the default gets header
// blocks it can decode: the shaper's encoder shrinks its table with the
// Transport's.
func TestKilvaterSmallServerHeaderTable(t *testing.T) {
	key, hexKey := kilTestKey(t)
	srv := kilServerFor(key)
	dial := func(ctx context.Context) (net.Conn, error) {
		c, s := net.Pipe()
		t.Cleanup(func() { s.Close() })
		go (&http2.Server{MaxDecoderHeaderTableSize: 64}).ServeConn(s, &http2.ServeConnOpts{Handler: srv})
		return c, nil
	}
	w, err := newKilWire(kilTestSpec(hexKey), dial)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := 0; i < 3; i++ {
		flowEchoOver(t, w)
	}
}

// The Transport kilvater uses says what the shaper sends: its SETTINGS
// values and window are the profile's, before any reordering.
func TestChromeH2TransportValues(t *testing.T) {
	c, s := tcpPair(t)
	tr := chromeH2.transport(time.Minute, time.Second)
	go tr.NewClientConn(c)
	s.SetReadDeadline(time.Now().Add(5 * time.Second))
	pre := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(s, pre); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(nil, s)
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	got := map[http2.SettingID]uint32{}
	f.(*http2.SettingsFrame).ForeachSetting(func(st http2.Setting) error { got[st.ID] = st.Val; return nil })
	want := map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize: chromeH2.headerTable, http2.SettingEnablePush: 0,
		http2.SettingInitialWindowSize: chromeH2.streamWindow, http2.SettingMaxHeaderListSize: chromeH2.maxHeaderList,
		http2.SettingMaxFrameSize: 16384}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Transport SETTINGS %v, want %v", got, want)
	}
	f, err = fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if wu, ok := f.(*http2.WindowUpdateFrame); !ok || wu.Increment != chromeH2.connWindow {
		t.Fatalf("after SETTINGS %v, want WINDOW_UPDATE %d", f, chromeH2.connWindow)
	}
}

func TestPageAssets(t *testing.T) {
	page := []byte(`<html><head><link rel="icon" href="/f.ico"><link href='/s.css?v=2#x' rel=stylesheet>
<script src="https://cdn.example/x.js"></script><script src="js/app.js"></script>
<img src="//other.example/i.png"><img src="/i.png"></head></html>`)
	got := pageAssets(page, 3)
	want := []pageAsset{{"/s.css?v=2", "style"}, {"/js/app.js", "script"}, {"/i.png", "image"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pageAssets = %v, want %v", got, want)
	}
	if got := pageAssets(page, 1); len(got) != 1 {
		t.Fatalf("limit 1 gave %d", len(got))
	}
}
