// Package ja4 computes the JA4 fingerprint of a TLS ClientHello, the form
// passive fingerprinting uses today (FoxIO JA4, TLS client part). It exists
// to compare what the core sends with what a browser sends: the extension
// order Chrome shuffles per connection does not change it.
package ja4

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Hello is what JA4 reads of a ClientHello.
type Hello struct {
	Version    uint16   // the highest offered: supported_versions, else the legacy field
	SNI        bool     // a server_name extension is present
	Ciphers    []uint16 // in order, GREASE dropped
	Extensions []uint16 // in order, GREASE dropped
	ALPN       string   // the first protocol offered, "" if none
	SigAlgs    []uint16 // in order, GREASE dropped
}

func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

// ReadClientHello reads one TLS handshake message from r, across as many
// records as it takes, and returns its bytes from the handshake header on.
func ReadClientHello(r io.Reader) ([]byte, error) {
	var msg []byte
	for {
		var h [5]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return nil, err
		}
		if h[0] != 22 {
			return nil, fmt.Errorf("ja4: record type %d, not a handshake", h[0])
		}
		rec := make([]byte, int(h[3])<<8|int(h[4]))
		if _, err := io.ReadFull(r, rec); err != nil {
			return nil, err
		}
		msg = append(msg, rec...)
		if len(msg) >= 4 {
			if n := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3]); len(msg) >= 4+n {
				return msg[:4+n], nil
			}
		}
	}
}

type cursor struct {
	b   []byte
	bad bool
}

func (c *cursor) take(n int) []byte {
	if c.bad || n < 0 || len(c.b) < n {
		c.bad = true
		return nil
	}
	p := c.b[:n]
	c.b = c.b[n:]
	return p
}
func (c *cursor) u8() int {
	if p := c.take(1); p != nil {
		return int(p[0])
	}
	return 0
}
func (c *cursor) u16() int {
	if p := c.take(2); p != nil {
		return int(p[0])<<8 | int(p[1])
	}
	return 0
}

// Parse reads a ClientHello handshake message (from its 4-byte header).
func Parse(msg []byte) (Hello, error) {
	var h Hello
	if len(msg) < 4 || msg[0] != 1 {
		return h, errors.New("ja4: not a ClientHello")
	}
	c := &cursor{b: msg[4:]}
	h.Version = uint16(c.u16())
	c.take(32)
	c.take(c.u8())
	cs := &cursor{b: c.take(c.u16())}
	for len(cs.b) >= 2 {
		if v := uint16(cs.u16()); !isGREASE(v) {
			h.Ciphers = append(h.Ciphers, v)
		}
	}
	c.take(c.u8())
	if c.bad {
		return h, errors.New("ja4: short ClientHello")
	}
	if len(c.b) == 0 {
		return h, nil
	}
	ex := &cursor{b: c.take(c.u16())}
	for len(ex.b) >= 4 {
		typ := uint16(ex.u16())
		body := &cursor{b: ex.take(ex.u16())}
		if ex.bad {
			return h, errors.New("ja4: short extension")
		}
		if isGREASE(typ) {
			continue
		}
		h.Extensions = append(h.Extensions, typ)
		switch typ {
		case 0:
			h.SNI = true
		case 16:
			list := &cursor{b: body.take(body.u16())}
			if p := list.take(list.u8()); p != nil && h.ALPN == "" {
				h.ALPN = string(p)
			}
		case 13:
			list := &cursor{b: body.take(body.u16())}
			for len(list.b) >= 2 {
				if v := uint16(list.u16()); !isGREASE(v) {
					h.SigAlgs = append(h.SigAlgs, v)
				}
			}
		case 43:
			list := &cursor{b: body.take(body.u8())}
			var top uint16
			for len(list.b) >= 2 {
				if v := uint16(list.u16()); !isGREASE(v) && v > top {
					top = v
				}
			}
			if top != 0 {
				h.Version = top
			}
		}
	}
	return h, nil
}

func hexList(v []uint16, sorted bool) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = fmt.Sprintf("%04x", x)
	}
	if sorted {
		sort.Strings(s)
	}
	return strings.Join(s, ",")
}

func hash12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// Strings returns the JA4 fingerprint of h over TCP and its raw form
// (JA4_r), where the two hashes are spelled out.
func (h Hello) Strings() (ja4, raw string) {
	ver := "00"
	switch h.Version {
	case 0x0304:
		ver = "13"
	case 0x0303:
		ver = "12"
	case 0x0302:
		ver = "11"
	case 0x0301:
		ver = "10"
	}
	sni := "i"
	if h.SNI {
		sni = "d"
	}
	alpn := "00"
	if n := len(h.ALPN); n > 0 {
		alpn = string(h.ALPN[0]) + string(h.ALPN[n-1])
	}
	a := fmt.Sprintf("t%s%s%02d%02d%s", ver, sni, min(len(h.Ciphers), 99), min(len(h.Extensions), 99), alpn)
	var exts []uint16
	for _, e := range h.Extensions {
		if e != 0 && e != 16 {
			exts = append(exts, e)
		}
	}
	b := hexList(h.Ciphers, true)
	c := hexList(exts, true)
	if len(h.SigAlgs) > 0 {
		c += "_" + hexList(h.SigAlgs, false)
	}
	return a + "_" + hash12(b) + "_" + hash12(c), a + "_" + b + "_" + c
}

// Of is the JA4 of a ClientHello handshake message.
func Of(msg []byte) (ja4, raw string, err error) {
	h, err := Parse(msg)
	if err != nil {
		return "", "", err
	}
	ja4, raw = h.Strings()
	return ja4, raw, nil
}
