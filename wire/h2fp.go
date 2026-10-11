package wire

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// A browser's HTTP/2 differs from Go's in what goes into the frames: the
// SETTINGS and their order, the connection window, the order of the
// pseudo-headers and of the other headers, and a priority on every request.
// h2Shaper sits between the http2 Transport and the TLS connection and puts
// what the Transport writes into the browser's form. The Transport still runs
// the protocol (streams, flow control, pings); the values it advertises stay
// its own, configured to the browser's (h2Profile.transport), so the shaper
// only reorders and never claims a value the Transport does not use.
//
// chromeH2 was recorded from Chrome 154 into testdata/h2fp/chrome-154.json;
// TestKilvaterH2MatchesChrome holds the client to that file.

type h2Profile struct {
	headerTable   uint32 // SETTINGS_HEADER_TABLE_SIZE
	streamWindow  uint32 // SETTINGS_INITIAL_WINDOW_SIZE
	maxHeaderList uint32 // SETTINGS_MAX_HEADER_LIST_SIZE
	connWindow    uint32 // the WINDOW_UPDATE on the connection right after SETTINGS

	settings []http2.SettingID // the order SETTINGS go out in
	pseudo   []string          // the order of the pseudo-headers

	// The order of the other headers: on a page request (sec-fetch-mode:
	// navigate), and on every other request. Headers not listed follow in
	// the Transport's order.
	navigate, other []string
}

var chromeH2 = &h2Profile{
	headerTable:   65536,
	streamWindow:  6291456,
	maxHeaderList: 262144,
	connWindow:    15663105,
	settings: []http2.SettingID{http2.SettingHeaderTableSize, http2.SettingEnablePush,
		http2.SettingInitialWindowSize, http2.SettingMaxHeaderListSize},
	pseudo: []string{":method", ":authority", ":scheme", ":path"},
	navigate: []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests",
		"user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
		"accept-encoding", "accept-language", "priority"},
	other: []string{"content-length", "pragma", "cache-control", "sec-ch-ua-platform", "user-agent",
		"sec-ch-ua", "sec-ch-ua-mobile", "accept", "origin", "sec-fetch-site", "sec-fetch-mode",
		"sec-fetch-dest", "referer", "accept-encoding", "accept-language", "cookie", "priority"},
}

// h2ProfileFor is the HTTP/2 profile that goes with a link's TLS fingerprint,
// or nil to leave Go's HTTP/2 as it is: only a browser we have recorded gets
// one, so the TLS and HTTP/2 layers never name different browsers.
func h2ProfileFor(fp string) *h2Profile {
	if isChromeAuto(fp) {
		return chromeH2
	}
	return nil
}

// isChromeAuto reports whether a link's fp asks for the current Chrome rather
// than a specific pinned profile: the bare "chrome" or an empty default. Those
// get the live Chrome shape, at both the TLS (chromeAutoSpec) and HTTP/2
// (chromeH2) layers, so the two never name different browsers.
func isChromeAuto(fp string) bool {
	switch strings.ToLower(fp) {
	case "", "chrome":
		return true
	}
	return false
}

// transport is an http2 Transport whose own SETTINGS values and connection
// window are the profile's. Go adds the 65535 initial window to the
// connection buffer it is given, as the browser's increment does.
func (p *h2Profile) transport(pingAfterIdle, pingTimeout time.Duration) *http2.Transport {
	t1 := &http.Transport{HTTP2: &http.HTTP2Config{
		MaxReceiveBufferPerConnection: int(p.connWindow),
		MaxReceiveBufferPerStream:     int(p.streamWindow),
	}}
	t2, err := http2.ConfigureTransports(t1)
	if err != nil {
		// Only fails when t1 already has h2 set up, which a fresh one never has.
		panic(err)
	}
	t2.MaxDecoderHeaderTableSize = p.headerTable
	t2.MaxHeaderListSize = p.maxHeaderList
	t2.ReadIdleTimeout, t2.PingTimeout = pingAfterIdle, pingTimeout
	return t2
}

// shapedDial wraps a dialer's connections in the profile's shaper.
func shapedDial(dial func(context.Context) (net.Conn, error), p *h2Profile) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		c, err := dial(ctx)
		if err != nil {
			return nil, err
		}
		return newH2Shaper(c, p), nil
	}
}

const (
	h2FrameData         = 0x0
	h2FrameHeaders      = 0x1
	h2FrameRSTStream    = 0x3
	h2FrameSettings     = 0x4
	h2FrameContinuation = 0x9

	h2FlagEndStream  = 0x1
	h2FlagAck        = 0x1
	h2FlagEndHeaders = 0x4
	h2FlagPadded     = 0x8
	h2FlagPriority   = 0x20

	// h2MaxOutFrame bounds the HEADERS and CONTINUATION frames the shaper
	// writes: the spec's default SETTINGS_MAX_FRAME_SIZE, which every server
	// takes.
	h2MaxOutFrame = 16384
)

// h2Shaper rewrites the client side of one HTTP/2 connection (see the top of
// this file). Every frame passes through unchanged but SETTINGS, which are
// reordered, and header blocks, which are decoded from the Transport's HPACK
// and encoded again by the shaper's own encoder in the profile's order with a
// priority, so the server's decoder follows the shaper's encoder alone. It
// writes whole frames only, and what one Write of the Transport carried (one
// flush) still goes out as one write.
type h2Shaper struct {
	net.Conn
	p *h2Profile

	wmu     sync.Mutex
	werr    error
	preface bool
	wbuf    []byte // the tail of a frame the Transport has not finished writing
	out     []byte
	dec     *hpack.Decoder
	enc     *hpack.Encoder
	encBuf  bytes.Buffer
	block   []byte // a header block gathered across CONTINUATION frames
	blockID uint32
	blockES bool // END_STREAM was on the block's HEADERS frame

	// Streams the priorities are worked out from. The read side sees the
	// server end them.
	mu      sync.Mutex
	streams map[uint32]*h2ShapedStream
	open    [8][]uint32 // open stream IDs by urgency, oldest first
	rhdr    []byte
	rskip   int
}

type h2ShapedStream struct {
	urgency           int
	clientEnd, srvEnd bool
}

func newH2Shaper(c net.Conn, p *h2Profile) *h2Shaper {
	s := &h2Shaper{Conn: c, p: p, streams: map[uint32]*h2ShapedStream{}}
	// The Transport's encoder never goes past the spec's 4096-byte table
	// (http2.Transport.MaxEncoderHeaderTableSize unset), nor does ours.
	s.dec = hpack.NewDecoder(4096, nil)
	s.enc = hpack.NewEncoder(&s.encBuf)
	return s
}

var errH2Shaper = errors.New("h2shaper: malformed frame from the transport")

func (s *h2Shaper) Write(p []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.werr != nil {
		return 0, s.werr
	}
	b := p
	if len(s.wbuf) > 0 {
		s.wbuf = append(s.wbuf, p...)
		b = s.wbuf
	}
	out := s.out[:0]
	if !s.preface {
		if len(b) < len(http2.ClientPreface) {
			s.keep(b)
			return len(p), nil
		}
		out = append(out, b[:len(http2.ClientPreface)]...)
		b = b[len(http2.ClientPreface):]
		s.preface = true
	}
	for len(b) >= 9 {
		n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
		if len(b) < 9+n {
			break
		}
		typ, flags := b[3], b[4]
		id := binary.BigEndian.Uint32(b[5:9]) & (1<<31 - 1)
		payload := b[9 : 9+n]
		var err error
		switch {
		case typ == h2FrameSettings && flags&h2FlagAck == 0:
			out = s.settings(out, payload)
		case typ == h2FrameHeaders || typ == h2FrameContinuation:
			out, err = s.headers(out, typ, flags, id, payload)
		default:
			out = append(out, b[:9+n]...)
			s.clientFrame(typ, flags, id)
		}
		if err != nil {
			s.werr = err
			return 0, err
		}
		b = b[9+n:]
	}
	s.keep(b)
	if len(out) > 0 {
		if _, err := s.Conn.Write(out); err != nil {
			s.werr = err
			return 0, err
		}
	}
	s.out = out[:0]
	return len(p), nil
}

// keep holds b, the unfinished tail of what was written, for the next Write.
// b may lie inside wbuf itself; copy moves it safely.
func (s *h2Shaper) keep(b []byte) {
	if len(s.wbuf) > 0 && len(b) > 0 && &b[0] == &s.wbuf[len(s.wbuf)-len(b)] {
		s.wbuf = s.wbuf[:copy(s.wbuf, b)]
		return
	}
	s.wbuf = append(s.wbuf[:0], b...)
}

func appendFrameHeader(out []byte, n int, typ, flags byte, id uint32) []byte {
	return append(out, byte(n>>16), byte(n>>8), byte(n), typ, flags,
		byte(id>>24), byte(id>>16), byte(id>>8), byte(id))
}

// settings writes the Transport's SETTINGS in the profile's order. A setting
// the profile does not send is dropped only when it holds the protocol
// default, so dropping it changes nothing; any other keeps its place after
// the profile's.
func (s *h2Shaper) settings(out []byte, payload []byte) []byte {
	type kv struct {
		id  http2.SettingID
		val uint32
	}
	var all []kv
	for i := 0; i+6 <= len(payload); i += 6 {
		all = append(all, kv{http2.SettingID(binary.BigEndian.Uint16(payload[i:])), binary.BigEndian.Uint32(payload[i+2:])})
	}
	var sorted []kv
	for _, id := range s.p.settings {
		for _, e := range all {
			if e.id == id {
				sorted = append(sorted, e)
			}
		}
	}
	for _, e := range all {
		listed := false
		for _, id := range s.p.settings {
			listed = listed || e.id == id
		}
		if !listed && !(e.id == http2.SettingMaxFrameSize && e.val == 16384) {
			sorted = append(sorted, e)
		}
	}
	out = appendFrameHeader(out, 6*len(sorted), h2FrameSettings, 0, 0)
	for _, e := range sorted {
		out = binary.BigEndian.AppendUint16(out, uint16(e.id))
		out = binary.BigEndian.AppendUint32(out, e.val)
	}
	return out
}

// headers gathers a header block (HEADERS, then any CONTINUATION) and, once
// it is whole, writes it out again in the profile's form.
func (s *h2Shaper) headers(out []byte, typ, flags byte, id uint32, payload []byte) ([]byte, error) {
	if typ == h2FrameHeaders {
		if s.block != nil {
			return out, errH2Shaper
		}
		if flags&h2FlagPadded != 0 {
			if len(payload) < 1 || int(payload[0]) > len(payload)-1 {
				return out, errH2Shaper
			}
			payload = payload[1 : len(payload)-int(payload[0])]
		}
		if flags&h2FlagPriority != 0 {
			if len(payload) < 5 {
				return out, errH2Shaper
			}
			payload = payload[5:]
		}
		s.block, s.blockID, s.blockES = append([]byte{}, payload...), id, flags&h2FlagEndStream != 0
	} else {
		if s.block == nil || id != s.blockID {
			return out, errH2Shaper
		}
		s.block = append(s.block, payload...)
	}
	if flags&h2FlagEndHeaders == 0 {
		return out, nil
	}
	block := s.block
	s.block = nil
	// A table size change the Transport's encoder made (after the server's
	// SETTINGS_HEADER_TABLE_SIZE) is made by ours too.
	for rest := block; len(rest) > 0 && rest[0]&0xe0 == 0x20; {
		v, r, ok := hpackInt(rest, 5)
		if !ok {
			return out, errH2Shaper
		}
		s.enc.SetMaxDynamicTableSize(uint32(v))
		rest = r
	}
	fields, err := s.dec.DecodeFull(block)
	if err != nil {
		return out, err
	}
	var prio []byte
	if isRequest(fields) {
		fields = s.p.order(fields)
		dep, weight := s.newStream(id, fields, s.blockES)
		prio = []byte{byte(dep>>24) | 0x80, byte(dep >> 16), byte(dep >> 8), byte(dep), byte(weight - 1)}
	} else if s.blockES {
		s.clientFrame(h2FrameHeaders, h2FlagEndStream, id)
	}
	s.encBuf.Reset()
	for _, f := range fields {
		if err := s.enc.WriteField(f); err != nil {
			return out, err
		}
	}
	enc := s.encBuf.Bytes()
	first := min(len(enc), h2MaxOutFrame-len(prio))
	fl := byte(0)
	if s.blockES {
		fl |= h2FlagEndStream
	}
	if prio != nil {
		fl |= h2FlagPriority
	}
	if first == len(enc) {
		fl |= h2FlagEndHeaders
	}
	out = appendFrameHeader(out, len(prio)+first, h2FrameHeaders, fl, id)
	out = append(append(out, prio...), enc[:first]...)
	for enc = enc[first:]; len(enc) > 0; {
		n := min(len(enc), h2MaxOutFrame)
		fl := byte(0)
		if n == len(enc) {
			fl = h2FlagEndHeaders
		}
		out = append(appendFrameHeader(out, n, h2FrameContinuation, fl, id), enc[:n]...)
		enc = enc[n:]
	}
	return out, nil
}

func isRequest(fields []hpack.HeaderField) bool {
	for _, f := range fields {
		if f.Name == ":method" {
			return true
		}
	}
	return false
}

// order puts a request's fields in the profile's order.
func (p *h2Profile) order(fields []hpack.HeaderField) []hpack.HeaderField {
	out := make([]hpack.HeaderField, 0, len(fields))
	used := make([]bool, len(fields))
	take := func(name string) {
		for i, f := range fields {
			if !used[i] && f.Name == name {
				out, used[i] = append(out, f), true
			}
		}
	}
	for _, n := range p.pseudo {
		take(n)
	}
	for i, f := range fields { // a pseudo-header the profile does not order
		if !used[i] && strings.HasPrefix(f.Name, ":") {
			out, used[i] = append(out, f), true
		}
	}
	list := p.other
	for _, f := range fields {
		if f.Name == "sec-fetch-mode" && f.Value == "navigate" {
			list = p.navigate
		}
	}
	for _, n := range list {
		take(n)
	}
	for i, f := range fields {
		if !used[i] {
			out = append(out, f)
		}
	}
	return out
}

// hpackInt reads an HPACK integer with an n-bit prefix (RFC 7541 §5.1).
func hpackInt(b []byte, n uint) (uint64, []byte, bool) {
	if len(b) == 0 {
		return 0, nil, false
	}
	max := uint64(1)<<n - 1
	v := uint64(b[0]) & max
	b = b[1:]
	if v < max {
		return v, b, true
	}
	for shift := uint(0); len(b) > 0 && shift <= 28; shift += 7 {
		c := b[0]
		b = b[1:]
		v += uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, b, true
		}
	}
	return 0, nil, false
}

// urgency is the u= of a request's priority header, 3 without one (RFC 9218).
func urgency(fields []hpack.HeaderField) int {
	for _, f := range fields {
		if f.Name != "priority" {
			continue
		}
		for _, p := range strings.Split(f.Value, ",") {
			if p = strings.TrimSpace(p); strings.HasPrefix(p, "u=") {
				if u, err := strconv.Atoi(p[2:]); err == nil && u >= 0 && u <= 7 {
					return u
				}
			}
		}
	}
	return 3
}

// newStream records a request stream and returns the priority Chrome gives
// it: an exclusive dependency on the newest open stream of the same urgency,
// else of the nearest more urgent one, else none, and a weight from the
// urgency (net/spdy Http2PriorityDependencies, Spdy3PriorityToHttp2Weight).
func (s *h2Shaper) newStream(id uint32, fields []hpack.HeaderField, ended bool) (dep uint32, weight int) {
	u := urgency(fields)
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := u; i >= 0; i-- {
		if l := s.open[i]; len(l) > 0 {
			dep = l[len(l)-1]
			break
		}
	}
	s.streams[id] = &h2ShapedStream{urgency: u, clientEnd: ended}
	s.open[u] = append(s.open[u], id)
	return dep, int(255.9/7*float64(7-u)) + 1
}

func (s *h2Shaper) clientFrame(typ, flags byte, id uint32) {
	switch {
	case typ == h2FrameRSTStream:
		s.ended(id, true, true)
	case (typ == h2FrameData || typ == h2FrameHeaders) && flags&h2FlagEndStream != 0:
		s.ended(id, true, false)
	}
}

// ended marks one side of a stream finished (both, on a reset) and forgets
// the stream once it is closed.
func (s *h2Shaper) ended(id uint32, client, reset bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.streams[id]
	if st == nil {
		return
	}
	if client || reset {
		st.clientEnd = true
	}
	if !client || reset {
		st.srvEnd = true
	}
	if !st.clientEnd || !st.srvEnd {
		return
	}
	delete(s.streams, id)
	l := s.open[st.urgency]
	for i, v := range l {
		if v == id {
			s.open[st.urgency] = append(l[:i], l[i+1:]...)
			break
		}
	}
}

// Read passes the server's bytes through and notes the streams it ends.
func (s *h2Shaper) Read(p []byte) (int, error) {
	n, err := s.Conn.Read(p)
	b := p[:n]
	for len(b) > 0 {
		if s.rskip > 0 {
			k := min(s.rskip, len(b))
			s.rskip -= k
			b = b[k:]
			continue
		}
		k := min(9-len(s.rhdr), len(b))
		s.rhdr = append(s.rhdr, b[:k]...)
		b = b[k:]
		if len(s.rhdr) < 9 {
			break
		}
		h := s.rhdr
		typ, flags := h[3], h[4]
		id := binary.BigEndian.Uint32(h[5:9]) & (1<<31 - 1)
		switch {
		case typ == h2FrameRSTStream:
			s.ended(id, false, true)
		case (typ == h2FrameData || typ == h2FrameHeaders) && flags&h2FlagEndStream != 0:
			s.ended(id, false, false)
		}
		s.rskip = int(h[0])<<16 | int(h[1])<<8 | int(h[2])
		s.rhdr = s.rhdr[:0]
	}
	return n, err
}
