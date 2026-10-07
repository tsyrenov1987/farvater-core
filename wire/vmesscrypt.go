package wire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"hash/crc32"
	"hash/fnv"

	"golang.org/x/crypto/sha3"
)

// This file is our own VMess AEAD cryptography: the key derivation, the
// sealed request header, and the authenticated chunk stream. The wire format
// matches Xray's so our client talks to an Xray server.

const vmessKDFSalt = "VMess AEAD KDF"

// wrapHash makes a distinct hash.Hash value that behaves identically to the
// one it wraps, so a generator can hand crypto/hmac two different values that
// are really the same instance (Go's HMAC rejects a generator whose two
// calls return the same value).
type wrapHash struct{ hash.Hash }

// vmessKDF is VMess's nested-HMAC key derivation: each path element rekeys an
// HMAC whose own hash is the previous stage.
func vmessKDF(key []byte, path ...string) []byte {
	h := hmac.New(sha256.New, []byte(vmessKDFSalt))
	for _, p := range path {
		prev := h
		first := true
		h = hmac.New(func() hash.Hash {
			if first {
				first = false
				return wrapHash{prev}
			}
			return prev
		}, []byte(p))
	}
	h.Write(key)
	return h.Sum(nil)
}

func vmessKDF16(key []byte, path ...string) []byte { return vmessKDF(key, path...)[:16] }

// vmessCmdKey is MD5(uuid || the VMess command-key magic), as Xray derives it.
func vmessCmdKey(uuid []byte) []byte {
	h := md5.New()
	h.Write(uuid)
	h.Write([]byte("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
	return h.Sum(nil)
}

// sealVMessAEADHeader wraps the request header as VMess AEAD: an auth id
// derived from the command key and the time, then the length and the header
// each sealed with keys derived from the id and a fresh nonce.
func sealVMessAEADHeader(cmdKey, header []byte, now int64) ([]byte, error) {
	authID, err := vmessAuthID(cmdKey, now)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	lenKey := vmessKDF16(cmdKey, "VMess Header AEAD Key_Length", string(authID[:]), string(nonce))
	lenNonce := vmessKDF(cmdKey, "VMess Header AEAD Nonce_Length", string(authID[:]), string(nonce))[:12]
	lenAEAD, err := newAESGCM(lenKey)
	if err != nil {
		return nil, err
	}
	var lenPlain [2]byte
	binary.BigEndian.PutUint16(lenPlain[:], uint16(len(header)))
	encLen := lenAEAD.Seal(nil, lenNonce, lenPlain[:], authID[:])

	payKey := vmessKDF16(cmdKey, "VMess Header AEAD Key", string(authID[:]), string(nonce))
	payNonce := vmessKDF(cmdKey, "VMess Header AEAD Nonce", string(authID[:]), string(nonce))[:12]
	payAEAD, err := newAESGCM(payKey)
	if err != nil {
		return nil, err
	}
	encPay := payAEAD.Seal(nil, payNonce, header, authID[:])

	out := make([]byte, 0, 16+len(encLen)+8+len(encPay))
	out = append(out, authID[:]...)
	out = append(out, encLen...)
	out = append(out, nonce...)
	out = append(out, encPay...)
	return out, nil
}

// vmessAuthID is the 16-byte authentication id: the time and a CRC32 of it,
// encrypted with a key derived from the command key.
func vmessAuthID(cmdKey []byte, now int64) ([16]byte, error) {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[:8], uint64(now))
	if _, err := rand.Read(buf[8:12]); err != nil {
		return buf, err
	}
	binary.BigEndian.PutUint32(buf[12:], crc32.ChecksumIEEE(buf[:12]))
	block, err := aes.NewCipher(vmessKDF16(cmdKey, "AES Auth ID Encryption"))
	if err != nil {
		return buf, err
	}
	var out [16]byte
	block.Encrypt(out[:], buf[:])
	return out, nil
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// vmessChachaKey expands a 16-byte key to the 32 bytes ChaCha20 needs, as
// VMess does: md5(key) then md5 of that.
func vmessChachaKey(key []byte) []byte {
	out := make([]byte, 32)
	t := md5.Sum(key)
	copy(out, t[:])
	t = md5.Sum(out[:16])
	copy(out[16:], t[:])
	return out
}

// shakeSizeParser masks each chunk length with a SHAKE128 keystream and
// yields the global padding lengths, exactly as VMess's chunk masking does.
type shakeSizeParser struct {
	shake sha3.ShakeHash
	buf   [2]byte
}

func newShakeSizeParser(nonce []byte) *shakeSizeParser {
	s := sha3.NewShake128()
	s.Write(nonce)
	return &shakeSizeParser{shake: s}
}

func (s *shakeSizeParser) next() uint16 {
	s.shake.Read(s.buf[:])
	return binary.BigEndian.Uint16(s.buf[:])
}

func (s *shakeSizeParser) encode(size uint16) uint16   { return s.next() ^ size }
func (s *shakeSizeParser) decode(masked uint16) uint16 { return s.next() ^ masked }
func (s *shakeSizeParser) nextPadding() uint16         { return s.next() % 64 }

// vmessAEAD is the chunk cipher: an AEAD and the per-chunk nonce generator
// (a 2-byte counter prefixed to the IV tail).
type vmessAEAD struct {
	aead  cipher.AEAD
	iv    []byte
	count uint16
}

func (v *vmessAEAD) nonce() []byte {
	n := make([]byte, v.aead.NonceSize())
	binary.BigEndian.PutUint16(n, v.count)
	copy(n[2:], v.iv[2:v.aead.NonceSize()])
	v.count++
	return n
}

// noopAEAD is VMess's security=none: framed and masked, but not encrypted
// (the outer TLS already encrypts).
type noopAEAD struct{}

func (noopAEAD) NonceSize() int { return 0 }
func (noopAEAD) Overhead() int  { return 0 }
func (noopAEAD) Seal(dst, _, plaintext, _ []byte) []byte {
	return append(dst, plaintext...)
}
func (noopAEAD) Open(dst, _, ciphertext, _ []byte) ([]byte, error) {
	return append(dst, ciphertext...), nil
}

// fnv1a32 is VMess's header checksum.
func fnv1a32(b []byte) uint32 {
	h := fnv.New32a()
	h.Write(b)
	return h.Sum32()
}
