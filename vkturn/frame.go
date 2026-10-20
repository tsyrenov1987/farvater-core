// Package vkturn carries a path's TCP connection through VK's call relays
// (TURN): where an allow-list lets VK calls through and nothing else, the
// relays are the way out. The client spreads one KCP conversation over
// several relay allocations; the server on the node gathers it back and
// hands each stream to the node's own proxy inbound. The wire format is the
// one orden-vkturn's server speaks.
package vkturn

// Packets are sealed to look like SRTP video: a plain RTP header followed by
// what looks like encrypted media. VK's relays drop UDP that does not look
// like call media, and RTP with a running sequence passes at about 2 Mbit/s
// per allocation (measured 19.10.2026).

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	rtpLen   = 12
	sidLen   = 8
	Overhead = rtpLen + chacha20poly1305.NonceSizeX + sidLen + chacha20poly1305.Overhead
)

// SessionID ties together the channels of one client: each channel reaches
// the server from a different relay address.
type SessionID [sidLen]byte

// Stream is one RTP stream: its SSRC, sequence and timestamp advance like
// a 30 fps video track.
type Stream struct {
	ssrc uint32
	seq  uint16
	ts   uint32
}

func NewStream() *Stream {
	var b [8]byte
	rand.Read(b[:])
	return &Stream{ssrc: binary.BigEndian.Uint32(b[:4]), seq: binary.BigEndian.Uint16(b[4:6])}
}

type Sealer struct{ key []byte }

func NewSealer(psk []byte) (*Sealer, error) {
	if len(psk) != chacha20poly1305.KeySize {
		return nil, errors.New("frame: psk must be 32 bytes")
	}
	return &Sealer{key: psk}, nil
}

// Seal appends one packet carrying payload for session sid to dst.
func (s *Sealer) Seal(dst []byte, st *Stream, sid SessionID, payload []byte) []byte {
	st.seq++
	st.ts += 3000
	var h [rtpLen]byte
	h[0], h[1] = 0x80, 0x60
	binary.BigEndian.PutUint16(h[2:], st.seq)
	binary.BigEndian.PutUint32(h[4:], st.ts)
	binary.BigEndian.PutUint32(h[8:], st.ssrc)
	dst = append(dst, h[:]...)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	rand.Read(nonce)
	dst = append(dst, nonce...)
	plain := make([]byte, 0, sidLen+len(payload))
	plain = append(plain, sid[:]...)
	plain = append(plain, payload...)
	aead, _ := chacha20poly1305.NewX(s.key)
	return aead.Seal(dst, nonce, plain, h[:])
}

var ErrBad = errors.New("frame: not ours")

// Open checks and decrypts a packet; anything that is not ours is ErrBad.
func (s *Sealer) Open(pkt []byte) (SessionID, []byte, error) {
	var sid SessionID
	if len(pkt) < Overhead || pkt[0]&0xc0 != 0x80 {
		return sid, nil, ErrBad
	}
	aead, _ := chacha20poly1305.NewX(s.key)
	nonce := pkt[rtpLen : rtpLen+chacha20poly1305.NonceSizeX]
	plain, err := aead.Open(nil, nonce, pkt[rtpLen+chacha20poly1305.NonceSizeX:], pkt[:rtpLen])
	if err != nil {
		return sid, nil, ErrBad
	}
	copy(sid[:], plain)
	return sid, plain[sidLen:], nil
}
