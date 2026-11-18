package kilvater

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// The split transport (split.go) runs through a CDN, and a CDN ends TLS at
// its edge: everything inside the HTTP requests, the OPEN frame's target
// included, is plaintext there. So in split mode the frame stream is sealed
// once more, end to end between client and server, with a key both derive
// from the tunnel key and the session id. The edge sees record lengths and
// timing, as it would of any streamed response, and nothing else.
//
// A sealed stream is a run of records:
//
//	len  uint16  length of the ciphertext that follows (tag included)
//	ct   []byte  ChaCha20-Poly1305 of up to sealMaxPlain bytes
//
// The nonce is the record's number, counted from 0 in each direction; the
// two directions have their own keys, so a nonce never repeats under a key.

const (
	sealMaxPlain = 16 << 10
	sealOverhead = chacha20poly1305.Overhead
)

// Directions of a sealed split session.
const (
	SealUp   = "up"   // client to server
	SealDown = "down" // server to client
)

// ErrSealOpen is a record that does not authenticate: tampered with on the
// way, or not sealed with this session's key.
var ErrSealOpen = errors.New("kilvater: sealed record does not authenticate")

func sealAEAD(k Key, sid []byte, dir string) cipher.AEAD {
	out, err := hkdf.Key(sha256.New, k[:], sid, "kilvater split seal "+dir, chacha20poly1305.KeySize)
	if err != nil {
		panic("kilvater: hkdf: " + err.Error())
	}
	a, err := chacha20poly1305.New(out)
	if err != nil {
		panic("kilvater: chacha20poly1305: " + err.Error())
	}
	return a
}

// SealWriter seals what is written to it, a record per Write (a long Write
// is cut into several), and writes the records to w.
type SealWriter struct {
	mu  sync.Mutex
	w   io.Writer
	a   cipher.AEAD
	n   uint64
	buf []byte
}

func NewSealWriter(w io.Writer, k Key, sid []byte, dir string) *SealWriter {
	return &SealWriter{w: w, a: sealAEAD(k, sid, dir)}
}

func (s *SealWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	done := 0
	for len(p) > 0 {
		n := min(len(p), sealMaxPlain)
		var nonce [chacha20poly1305.NonceSize]byte
		binary.BigEndian.PutUint64(nonce[4:], s.n)
		s.n++
		s.buf = append(s.buf[:0], 0, 0)
		s.buf = s.a.Seal(s.buf, nonce[:], p[:n], nil)
		binary.BigEndian.PutUint16(s.buf, uint16(len(s.buf)-2))
		if _, err := s.w.Write(s.buf); err != nil {
			return done, err
		}
		done += n
		p = p[n:]
	}
	return done, nil
}

// SealReader opens the records read from r.
type SealReader struct {
	r    io.Reader
	a    cipher.AEAD
	n    uint64
	buf  []byte
	left []byte // opened, not yet read
}

func NewSealReader(r io.Reader, k Key, sid []byte, dir string) *SealReader {
	return &SealReader{r: r, a: sealAEAD(k, sid, dir), buf: make([]byte, sealMaxPlain+sealOverhead)}
}

func (s *SealReader) Read(p []byte) (int, error) {
	for len(s.left) == 0 {
		var hdr [2]byte
		if _, err := io.ReadFull(s.r, hdr[:]); err != nil {
			return 0, err
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if n < sealOverhead || n > len(s.buf) {
			return 0, ErrSealOpen
		}
		if _, err := io.ReadFull(s.r, s.buf[:n]); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		var nonce [chacha20poly1305.NonceSize]byte
		binary.BigEndian.PutUint64(nonce[4:], s.n)
		s.n++
		out, err := s.a.Open(s.buf[:0], nonce[:], s.buf[:n], nil)
		if err != nil {
			return 0, ErrSealOpen
		}
		s.left = out
	}
	n := copy(p, s.left)
	s.left = s.left[n:]
	return n, nil
}
