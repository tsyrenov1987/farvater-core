// Package kilvater holds the wire format of the private HTTPS transport shared
// by the client wire and the kilvaterd server (docs/KILVATER.md): the frames
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
	"sync/atomic"
	"time"
)

// Frame types. Type 4 is reserved for a future datagram frame: Kilvater
// carries TCP, and UDP flows ride the other paths in the fan.
const (
	FrameOpen  byte = 1 // body: network byte, target address
	FrameData  byte = 2 // body: payload
	FramePad   byte = 3 // body: ignored
	FrameClose byte = 5 // body: one code byte
)

// Networks named in an OPEN frame.
const (
	NetTCP byte = 1
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

// WritePad writes a PAD frame of a random length, so the size of the first
// records a session puts on the wire varies run to run. The body is ignored
// on read; only its length, which TLS passes through to the record size,
// carries any signal.
func WritePad(w io.Writer) error {
	var n [1]byte
	rand.Read(n[:])
	return WriteFrame(w, FramePad, make([]byte, 16+int(n[0])))
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

// verifiedV2 is Verify's non-negative result for an accepted v2 tag, which
// has no key index to return (the key is derived, not listed).
const verifiedV2 = 1 << 20

// keySet is a verifier's key material, immutable once built. A reload swaps
// the whole pointer atomically, so a concurrent Verify reads one consistent
// set; it gates only new streams, so a running tunnel is never touched.
type keySet struct {
	keys    []Key          // v1 flat keys, tried for a v1 tag
	master  *Key           // optional master for v2 derived keys
	revoked map[KeyID]bool // revoked v2 key ids
}

// Verifier checks tags against its key material and refuses a tag seen before.
// It accepts both v1 tags (trying each flat key) and v2 tags (deriving the key
// from the master by the tag's key id), and reloads without cutting sessions.
type Verifier struct {
	set atomic.Pointer[keySet]

	mu     sync.Mutex
	seen   map[[16]byte]int64 // tag MAC/nonce → ts, for TagWindow
	pruned int64
}

func NewVerifier(keys []Key) *Verifier {
	v := &Verifier{seen: make(map[[16]byte]int64)}
	v.set.Store(&keySet{keys: keys})
	return v
}

// VerifierConfig is a verifier's key material, for NewVerifierConfig and
// Reload (the shape a kilvaterd reload reads from its files).
type VerifierConfig struct {
	Keys    []Key   // v1 flat keys
	Master  *Key    // optional master enabling v2 derived keys
	Revoked []KeyID // revoked v2 key ids
}

// NewVerifierConfig builds a verifier from full key material (v1 keys, an
// optional v2 master, and a revocation list).
func NewVerifierConfig(cfg VerifierConfig) *Verifier {
	v := &Verifier{seen: make(map[[16]byte]int64)}
	v.Reload(cfg)
	return v
}

// Reload swaps in new key material. It does not touch live streams: Verify
// gates only new stream opens, so a reload (e.g. on SIGHUP to revoke one key)
// takes effect for the next authentication and leaves open tunnels running.
func (v *Verifier) Reload(cfg VerifierConfig) {
	rev := make(map[KeyID]bool, len(cfg.Revoked))
	for _, id := range cfg.Revoked {
		rev[id] = true
	}
	v.set.Store(&keySet{keys: cfg.Keys, master: cfg.Master, revoked: rev})
}

// Verify reports whether tag is valid for path now: a non-negative result
// accepts it (the matching v1 key index, or verifiedV2 for a v2 tag), -1
// rejects. A tag already seen within its window is rejected as a replay.
func (v *Verifier) Verify(tag, path string, now time.Time) int {
	b, err := base64.RawURLEncoding.DecodeString(tag)
	if err != nil {
		return -1
	}
	set := v.set.Load()
	switch {
	case len(b) == TagSize:
		return v.verifyV1(set, b, path, now)
	case len(b) == tagV2Size && b[0] == tagVersion2:
		return v.verifyV2(set, b, path, now)
	default:
		return -1
	}
}

func (v *Verifier) verifyV1(set *keySet, b []byte, path string, now time.Time) int {
	if !withinWindow(int64(binary.BigEndian.Uint64(b[:8])), now) {
		return -1
	}
	idx := -1
	for i, k := range set.keys {
		if hmac.Equal(mac(k, b[:8], b[8:16], path), b[16:]) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return -1
	}
	if !v.firstSeen(b[:16], int64(binary.BigEndian.Uint64(b[:8])), now) {
		return -1
	}
	return idx
}

func (v *Verifier) verifyV2(set *keySet, b []byte, path string, now time.Time) int {
	if set.master == nil {
		return -1
	}
	var id KeyID
	copy(id[:], b[1:1+KeyIDSize])
	off := 1 + KeyIDSize
	ts := int64(binary.BigEndian.Uint64(b[off : off+8]))
	if !withinWindow(ts, now) {
		return -1
	}
	if set.revoked[id] {
		return -1
	}
	want := macV2(DeriveKey(*set.master, id), id, b[off:off+8], b[off+8:off+16], path)
	tagMAC := b[off+16:]
	if !hmac.Equal(want, tagMAC) {
		return -1
	}
	// Key the replay set by the MAC: unique per client, ts and nonce, so two
	// clients that pick the same nonce are not taken for a replay of each other.
	if !v.firstSeen(tagMAC, ts, now) {
		return -1
	}
	return verifiedV2
}

func withinWindow(ts int64, now time.Time) bool {
	d := now.Unix() - ts
	w := int64(TagWindow / time.Second)
	return d <= w && d >= -w
}

// firstSeen records a 16-byte tag fingerprint and reports whether it is new
// within the window; a repeat is a replay. It prunes expired entries now and
// then so the set does not grow without bound.
func (v *Verifier) firstSeen(fp []byte, ts int64, now time.Time) bool {
	var id [16]byte
	copy(id[:], fp)
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, dup := v.seen[id]; dup {
		return false
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
	return true
}

// CookieName is the cookie that carries the tag.
const CookieName = "_sid"

// String keeps a Key out of logs and error texts.
func (k Key) String() string { return "kilvater.Key(redacted)" }

// GoString does the same for %#v.
func (k Key) GoString() string { return k.String() }
