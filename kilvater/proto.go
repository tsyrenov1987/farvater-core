// Package kilvater holds the wire format of the private HTTPS transport shared
// by the client wire and the kilvaterd server (KILVATER-SPEC.md): the frames
// that ride inside one HTTP/2 stream, and the request tag that tells the
// tunnel apart from an ordinary visit. TLS 1.3 underneath carries all of the
// confidentiality and integrity; nothing here encrypts.
package kilvater

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// Frame types.
const (
	FrameOpen  byte = 1 // body: network byte, target address
	FrameData  byte = 2 // body: payload
	FramePad   byte = 3 // body: ignored
	FrameDgram byte = 4 // body: address, payload
	FrameClose byte = 5 // body: one code byte
)

// Networks named in an OPEN frame.
const (
	NetTCP byte = 1
	NetUDP byte = 2
)

// MaxFrame caps a frame body. A length above it is a protocol error, never an
// allocation (the 3-byte length field could otherwise ask for 16 MiB).
const MaxFrame = 16 << 10

var ErrFrameTooLong = errors.New("kilvater: frame too long")

// WriteFrame writes one frame: [type:1][length:3][body].
func WriteFrame(w io.Writer, typ byte, body []byte) error {
	if len(body) > MaxFrame {
		return ErrFrameTooLong
	}
	b := make([]byte, 4+len(body))
	b[0] = typ
	b[1], b[2], b[3] = byte(len(body)>>16), byte(len(body)>>8), byte(len(body))
	copy(b[4:], body)
	_, err := w.Write(b)
	return err
}

// ReadFrame reads one frame into buf (grown as needed) and returns its type and body.
func ReadFrame(r io.Reader, buf []byte) (byte, []byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n := int(h[1])<<16 | int(h[2])<<8 | int(h[3])
	if n > MaxFrame {
		return 0, nil, ErrFrameTooLong
	}
	if cap(buf) < n {
		buf = make([]byte, n)
	}
	buf = buf[:n]
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return h[0], buf, nil
}

// AppendAddr appends a target as [length:1]["host:port"].
func AppendAddr(b []byte, hostport string) ([]byte, error) {
	if len(hostport) == 0 || len(hostport) > 255 {
		return nil, errors.New("kilvater: bad address")
	}
	return append(append(b, byte(len(hostport))), hostport...), nil
}

// ParseAddr reads an address written by AppendAddr and returns it with the rest of b.
func ParseAddr(b []byte) (string, []byte, error) {
	if len(b) < 1 || len(b) < 1+int(b[0]) || b[0] == 0 {
		return "", nil, errors.New("kilvater: bad address")
	}
	n := int(b[0])
	addr := string(b[1 : 1+n])
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return "", nil, errors.New("kilvater: bad address")
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return "", nil, errors.New("kilvater: bad address")
	}
	return addr, b[1+n:], nil
}

// Key is a client key: 32 bytes, written as 64 hex in links.
type Key [32]byte

// ParseKey parses 64 hex. The error never repeats the input.
func ParseKey(s string) (Key, error) {
	var k Key
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(k) {
		return k, errors.New("kilvater: key must be 64 hex")
	}
	copy(k[:], b)
	return k, nil
}

// TagSize is the raw tag length: unix seconds (8) + nonce (8) + MAC (16).
const TagSize = 32

// TagWindow is how far a tag's clock may be from the server's.
const TagWindow = 2 * time.Minute

func mac(k Key, ts, nonce []byte, path string) []byte {
	m := hmac.New(sha256.New, k[:])
	m.Write([]byte("kilvater/1\x00"))
	m.Write(ts)
	m.Write(nonce)
	m.Write([]byte(path))
	return m.Sum(nil)[:16]
}

// NewTag makes the request tag for path (the URL path the request goes to),
// base64url without padding, ready for a cookie value.
func NewTag(k Key, path string, now time.Time) string {
	b := make([]byte, TagSize)
	binary.BigEndian.PutUint64(b[:8], uint64(now.Unix()))
	rand.Read(b[8:16])
	copy(b[16:], mac(k, b[:8], b[8:16], path))
	return base64.RawURLEncoding.EncodeToString(b)
}

// Verifier checks tags against a set of keys and refuses a tag seen before.
type Verifier struct {
	keys []Key

	mu     sync.Mutex
	seen   map[[16]byte]int64 // ts+nonce → ts, for TagWindow
	pruned int64
}

func NewVerifier(keys []Key) *Verifier {
	return &Verifier{keys: keys, seen: make(map[[16]byte]int64)}
}

// Verify returns the index of the key that made tag, or -1.
func (v *Verifier) Verify(tag, path string, now time.Time) int {
	b, err := base64.RawURLEncoding.DecodeString(tag)
	if err != nil || len(b) != TagSize {
		return -1
	}
	ts := int64(binary.BigEndian.Uint64(b[:8]))
	if d := now.Unix() - ts; d > int64(TagWindow/time.Second) || d < -int64(TagWindow/time.Second) {
		return -1
	}
	idx := -1
	for i, k := range v.keys {
		if hmac.Equal(mac(k, b[:8], b[8:16], path), b[16:]) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return -1
	}
	var id [16]byte
	copy(id[:], b[:16])
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, dup := v.seen[id]; dup {
		return -1
	}
	if now.Unix()-v.pruned >= 10 {
		v.pruned = now.Unix()
		cut := now.Unix() - 2*int64(TagWindow/time.Second)
		for k, t := range v.seen {
			if t < cut {
				delete(v.seen, k)
			}
		}
	}
	v.seen[id] = ts
	return idx
}

// CookieName is the cookie that carries the tag.
const CookieName = "_sid"

// String keeps a Key out of logs and error texts.
func (k Key) String() string { return "kilvater.Key(redacted)" }

// GoString does the same for %#v.
func (k Key) GoString() string { return k.String() }
