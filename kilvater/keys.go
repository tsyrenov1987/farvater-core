package kilvater

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"
)

// Keys v2 (docs/KILVATER.md §7). A v1 tag carries no version and no key id, so
// the server tries every key and computes an HMAC for each (O(n) per request),
// and revoking one key means editing the key file. v2 puts a scheme version
// and a short key id in the tag, so the server verifies in O(1) by id; the key
// itself is derived from a master, so a worker hands each client its own key
// without a server-side file, and a single id can be revoked without touching
// the others. v1 tags are still accepted (Verifier), so deployed clients keep
// working until v2 has rolled out everywhere.

// KeyIDSize is the length of a v2 key id, in bytes.
const KeyIDSize = 8

// KeyID identifies a derived client key, on the wire (in the tag) and in a
// revocation list. It is opaque: it carries no subscriber information.
type KeyID [KeyIDSize]byte

// String prints a key id as hex.
func (id KeyID) String() string { return hex.EncodeToString(id[:]) }

const (
	tagVersion2 = 2
	// tagV2Size: version(1) + keyID(8) + unix seconds(8) + nonce(8) + MAC(16).
	tagV2Size = 1 + KeyIDSize + 8 + 8 + 16

	deriveInfo = "kilvater/key\x00" // HKDF info prefix for a client key
	kidInfo    = "kilvater/kid\x00" // HMAC prefix for a key id
	macV2Label = "kilvater/2\x00"   // domain of a v2 tag MAC
)

// DeriveKey computes a client key from the master and a key id:
//
//	K = HKDF-SHA256(secret = master, salt = "", info = "kilvater/key\0" || keyID, 32)
//
// The server derives K from the key id alone, so it never needs the worker's
// subscriber ids; the worker keeps the id-to-subscriber map. This is the
// canonical scheme a worker must match (docs/KILVATERD.md).
func DeriveKey(master Key, id KeyID) Key {
	out, err := hkdf.Key(sha256.New, master[:], nil, deriveInfo+string(id[:]), len(Key{}))
	if err != nil {
		// hkdf.Key only fails when the length is absurd; 32 never is.
		panic("kilvater: hkdf: " + err.Error())
	}
	var k Key
	copy(k[:], out)
	return k
}

// KeyIDFor allocates the key id for a subscriber under the master:
//
//	keyID = HMAC-SHA256(master, "kilvater/kid\0" || subscriber)[:8]
//
// It is how a worker should pick ids so they are opaque on the wire and need
// no stored map to re-derive the key. The server does not use it; it only ever
// sees the resulting id.
func KeyIDFor(master Key, subscriber []byte) KeyID {
	m := hmac.New(sha256.New, master[:])
	m.Write([]byte(kidInfo))
	m.Write(subscriber)
	var id KeyID
	copy(id[:], m.Sum(nil))
	return id
}

func macV2(k Key, id KeyID, ts, nonce []byte, path string) []byte {
	m := hmac.New(sha256.New, k[:])
	m.Write([]byte(macV2Label))
	m.Write(id[:])
	m.Write(ts)
	m.Write(nonce)
	m.Write([]byte(path))
	return m.Sum(nil)[:16]
}

// NewTagV2 makes a v2 request tag for path, base64url without padding, ready
// for a cookie value. It carries the scheme version and the key id, so the
// server verifies by id in O(1) rather than trying every key.
func NewTagV2(id KeyID, k Key, path string, now time.Time) string {
	b := make([]byte, tagV2Size)
	b[0] = tagVersion2
	copy(b[1:1+KeyIDSize], id[:])
	off := 1 + KeyIDSize
	binary.BigEndian.PutUint64(b[off:off+8], uint64(now.Unix()))
	rand.Read(b[off+8 : off+16])
	copy(b[off+16:], macV2(k, id, b[off:off+8], b[off+8:off+16], path))
	return base64.RawURLEncoding.EncodeToString(b)
}

// ParseKeyID parses 16 hex into a KeyID. The error never repeats the input.
func ParseKeyID(s string) (KeyID, error) {
	var id KeyID
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != KeyIDSize {
		return id, errors.New("kilvater: key id must be 16 hex")
	}
	copy(id[:], b)
	return id, nil
}
