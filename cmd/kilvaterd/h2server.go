package main

import (
	"encoding/binary"
	"math"
	"net"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// The server side of the HTTP/2 fingerprint, the counterpart of the client
// shaping in the wire package. A visitor without a key still finishes TLS and
// starts HTTP/2, and the server's SETTINGS and connection WINDOW_UPDATE go out
// before the first request — before any key is checked — so an active prober
// reads them without a key. Go's x/net/http2 server has a shape all its own:
// SETTINGS in the order MAX_FRAME_SIZE, MAX_CONCURRENT_STREAMS,
// MAX_HEADER_LIST_SIZE, HEADER_TABLE_SIZE, INITIAL_WINDOW_SIZE, a trailing
// NO_RFC7540_PRIORITIES, a ~1 MiB stream window — nothing like the nginx a real
// site runs.
//
// This matters behind a TLS-terminating proxy (the -h2c path, KILVATERD.md §9):
// there the TLS an observer sees is the proxy's OpenSSL, but the HTTP/2 is still
// kilvaterd's, so a Go HTTP/2 under an OpenSSL TLS is a mismatch of its own.
// nginxH2Server configures the server so the values it enforces are a stock
// nginx's, and shapeServerSettings reorders the SETTINGS frame to nginx's order
// and drops the settings nginx does not send. The wire result is nginx's
// server fingerprint, measured 2026-10-11 from stock public nginx sites
// (e.g. kernel.org), identical across them:
//
//	SETTINGS MAX_CONCURRENT_STREAMS=128, INITIAL_WINDOW_SIZE=65536,
//	MAX_FRAME_SIZE=16777215, then a connection WINDOW_UPDATE of 2147418112
//	(the window grown to 2^31-1).
//
// Only the -h2c path is shaped. On the direct-TLS path kilvaterd's TLS is Go's
// too, so a Go HTTP/2 there is consistent; faking nginx's HTTP/2 over Go's TLS
// would be a fresh mismatch, so that path keeps Go's HTTP/2 untouched.

// nginxSettings are the SETTINGS a stock nginx sends, in order. The shaper
// emits exactly these, each with the value the Go server actually enforces (set
// in nginxH2Server), so an advertised value never outruns the real one; it
// drops every other setting Go sends (HEADER_TABLE_SIZE 4096, which is the
// protocol default a peer assumes anyway, and MAX_HEADER_LIST_SIZE, which the
// server still enforces when decoding whether it announces it or not).
var nginxSettings = []http2.SettingID{
	http2.SettingMaxConcurrentStreams, // 0x3
	http2.SettingInitialWindowSize,    // 0x4
	http2.SettingMaxFrameSize,         // 0x5
}

const h2FrameSettings = 0x4

// nginxH2Server is the HTTP/2 server configured so the values it enforces are a
// stock nginx's. shapeServerSettings then puts the SETTINGS frame into nginx's
// order and set; together they present nginx's server fingerprint.
func nginxH2Server(idle time.Duration) *http2.Server {
	return &http2.Server{
		IdleTimeout:                  idle,
		MaxConcurrentStreams:         128,           // SETTINGS_MAX_CONCURRENT_STREAMS
		MaxUploadBufferPerStream:     65536,         // SETTINGS_INITIAL_WINDOW_SIZE
		MaxReadFrameSize:             1<<24 - 1,      // SETTINGS_MAX_FRAME_SIZE (16777215)
		MaxUploadBufferPerConnection: math.MaxInt32, // WINDOW_UPDATE grows the window to 2^31-1
		// nginx uses RFC 7540 priorities and so does not send
		// SETTINGS_NO_RFC7540_PRIORITIES; Go's default RFC 9218 scheduler does.
		// The RFC 7540 scheduler was x/net's own default for years.
		NewWriteScheduler: func() http2.WriteScheduler { return http2.NewPriorityWriteScheduler(nil) },
	}
}

// shapeServerSettings wraps a listener so each connection's first SETTINGS frame
// goes out in nginx's order and set (see nginxSettings).
func shapeServerSettings(ln net.Listener) net.Listener {
	return &shapedListener{Listener: ln}
}

type shapedListener struct{ net.Listener }

func (l *shapedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &settingsShaper{Conn: c}, nil
}

// settingsShaper reorders the server's own initial SETTINGS frame — the first
// thing the server writes — and then gets out of the way: once that frame has
// passed, Write is a straight pass-through, so the tunnel's data frames are not
// copied. The connection WINDOW_UPDATE that follows needs no reshaping; its
// value already comes out right from nginxH2Server's MaxUploadBufferPerConnection.
type settingsShaper struct {
	net.Conn
	mu   sync.Mutex
	done bool
	buf  []byte
}

func (s *settingsShaper) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return s.Conn.Write(p)
	}
	s.buf = append(s.buf, p...)
	if len(s.buf) < 9 {
		return len(p), nil // not even a frame header yet
	}
	n := int(s.buf[0])<<16 | int(s.buf[1])<<8 | int(s.buf[2])
	if len(s.buf) < 9+n {
		return len(p), nil // the whole SETTINGS frame has not arrived
	}
	// The server's first frame is its SETTINGS (the HTTP/2 server preface).
	var out []byte
	if typ, flags := s.buf[3], s.buf[4]; typ == h2FrameSettings && flags&0x1 == 0 {
		out = reorderSettings(s.buf[9 : 9+n])
	} else {
		out = append(out, s.buf[:9+n]...) // not what we expected: leave it be
	}
	out = append(out, s.buf[9+n:]...) // anything coalesced after it, unchanged
	s.buf = nil
	s.done = true
	if _, err := s.Conn.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// reorderSettings rebuilds a SETTINGS frame with only nginxSettings, in that
// order, each taking its value from payload (so the value stays the one the
// server enforces). Settings not in the list are dropped.
func reorderSettings(payload []byte) []byte {
	val := map[http2.SettingID]uint32{}
	for i := 0; i+6 <= len(payload); i += 6 {
		val[http2.SettingID(binary.BigEndian.Uint16(payload[i:]))] = binary.BigEndian.Uint32(payload[i+2:])
	}
	var body []byte
	for _, id := range nginxSettings {
		if v, ok := val[id]; ok {
			body = binary.BigEndian.AppendUint16(body, uint16(id))
			body = binary.BigEndian.AppendUint32(body, v)
		}
	}
	out := []byte{byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body)), h2FrameSettings, 0, 0, 0, 0, 0}
	return append(out, body...)
}
