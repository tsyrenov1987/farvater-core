package wire

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// wsMagic is RFC 6455's GUID for the Sec-WebSocket-Accept hash.
const wsMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// dialWS upgrades a TLS connection to WebSocket and returns a net.Conn that
// carries the tunnel as a stream of binary frames, the way Xray's client
// does: the path as the request URI, the Host header from the link's host
// setting (else the TLS name, else the server), ALPN http/1.1, and a browser
// set of request headers.
func dialWS(ctx context.Context, s PathSpec) (net.Conn, error) {
	u, err := dialSecure(ctx, s, true)
	if err != nil {
		return nil, err
	}
	c, err := wsUpgrade(ctx, u, s)
	if err != nil {
		u.Close()
		return nil, err
	}
	return c, nil
}

func wsUpgrade(ctx context.Context, conn net.Conn, s PathSpec) (net.Conn, error) {
	host := s.HostHeader
	if host == "" {
		host = s.ServerSNI()
	}
	path := s.Path
	if path == "" {
		path = "/"
	}
	reqURL := url.URL{Scheme: "https", Host: host, Path: path}

	var keyRaw [16]byte
	if _, err := rand.Read(keyRaw[:]); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyRaw[:])

	req := &http.Request{Method: http.MethodGet, URL: &reqURL, Host: host, Header: http.Header{}}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", key)
	browserHeaders(req.Header, "ws")

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	}
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, errors.New("websocket: the server answered " + resp.Status)
	}
	sum := sha1.Sum([]byte(key + wsMagic))
	if resp.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]) {
		return nil, errors.New("websocket: the server's accept key did not match")
	}
	_ = conn.SetDeadline(time.Time{})
	return &wsConn{conn: conn, br: br}, nil
}

// wsConn presents a WebSocket as a net.Conn. The client masks every frame
// (RFC 6455 §5.3); the server's frames are never masked. Control frames are
// answered or ignored; application bytes travel in binary frames.
type wsConn struct {
	conn net.Conn
	br   *bufio.Reader

	rmu  sync.Mutex
	rest int64 // payload left in the frame being read

	wmu sync.Mutex
}

const (
	wsBinary = 0x2
	wsClose  = 0x8
	wsPing   = 0x9
	wsPong   = 0xA

	// wsMaxFrame caps a frame's declared length so a malformed or hostile
	// server cannot make us allocate (or overflow int64 into) an arbitrary
	// size. The tunnel's own frames are far smaller; 64 MiB is generous.
	wsMaxFrame = 64 << 20
	// wsMaxControl is RFC 6455's limit on a control frame's payload.
	wsMaxControl = 125
)

func (w *wsConn) Read(p []byte) (int, error) {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	for w.rest == 0 {
		op, n, err := w.nextFrame()
		if err != nil {
			return 0, err
		}
		switch op {
		case wsBinary:
			w.rest = n
		case wsPing:
			payload := make([]byte, n)
			if _, err := io.ReadFull(w.br, payload); err != nil {
				return 0, err
			}
			if err := w.writeFrame(wsPong, payload); err != nil {
				return 0, err
			}
		case wsClose:
			return 0, io.EOF
		default: // pong, or a continuation of a binary frame we already drained
			if _, err := io.CopyN(io.Discard, w.br, n); err != nil {
				return 0, err
			}
		}
	}
	if int64(len(p)) > w.rest {
		p = p[:w.rest]
	}
	n, err := w.br.Read(p)
	w.rest -= int64(n)
	return n, err
}

// nextFrame reads a frame header and returns its opcode and payload length.
// The tunnel's frames are not fragmented, so a header's FIN is not examined.
func (w *wsConn) nextFrame() (op byte, n int64, err error) {
	var h [2]byte
	if _, err = io.ReadFull(w.br, h[:]); err != nil {
		return 0, 0, err
	}
	op = h[0] & 0x0f
	switch h[1] & 0x7f {
	case 126:
		var e [2]byte
		if _, err = io.ReadFull(w.br, e[:]); err != nil {
			return 0, 0, err
		}
		n = int64(binary.BigEndian.Uint16(e[:]))
	case 127:
		var e [8]byte
		if _, err = io.ReadFull(w.br, e[:]); err != nil {
			return 0, 0, err
		}
		n = int64(binary.BigEndian.Uint64(e[:]))
	default:
		n = int64(h[1] & 0x7f)
	}
	if h[1]&0x80 != 0 { // a server frame must not be masked, but drain one if it is
		var m [4]byte
		if _, err = io.ReadFull(w.br, m[:]); err != nil {
			return 0, 0, err
		}
	}
	if n < 0 || n > wsMaxFrame { // negative means the 8-byte length overflowed int64
		return 0, 0, errors.New("ws: frame length out of range")
	}
	if op >= wsClose && n > wsMaxControl { // control frames carry at most 125 bytes
		return 0, 0, errors.New("ws: control frame too long")
	}
	return op, n, nil
}

func (w *wsConn) Write(p []byte) (int, error) {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	if err := w.writeFrame(wsBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsConn) writeFrame(op byte, p []byte) error {
	var h []byte
	h = append(h, 0x80|op) // FIN + opcode
	n := len(p)
	switch {
	case n < 126:
		h = append(h, 0x80|byte(n))
	case n < 1<<16:
		h = append(h, 0x80|126)
		h = binary.BigEndian.AppendUint16(h, uint16(n))
	default:
		h = append(h, 0x80|127)
		h = binary.BigEndian.AppendUint64(h, uint64(n))
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	h = append(h, mask[:]...)
	masked := make([]byte, n)
	for i := range p {
		masked[i] = p[i] ^ mask[i&3]
	}
	if _, err := w.conn.Write(append(h, masked...)); err != nil {
		return err
	}
	return nil
}

func (w *wsConn) Close() error                       { return w.conn.Close() }
func (w *wsConn) LocalAddr() net.Addr                { return w.conn.LocalAddr() }
func (w *wsConn) RemoteAddr() net.Addr               { return w.conn.RemoteAddr() }
func (w *wsConn) SetDeadline(t time.Time) error      { return w.conn.SetDeadline(t) }
func (w *wsConn) SetReadDeadline(t time.Time) error  { return w.conn.SetReadDeadline(t) }
func (w *wsConn) SetWriteDeadline(t time.Time) error { return w.conn.SetWriteDeadline(t) }

var _ net.Conn = (*wsConn)(nil)
