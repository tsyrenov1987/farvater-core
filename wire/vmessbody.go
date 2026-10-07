package wire

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
)

// vmessChunkWriter frames the VMess body as authenticated chunks: each chunk
// is [size:2][sealed data][padding], the size masked by the shake stream and
// the padding length taken from it when global padding is on. An empty final
// chunk marks the end.
type vmessChunkWriter struct {
	w       io.Writer
	aead    cipher.AEAD
	nonce   func() []byte
	size    *shakeSizeParser // nil: a plain 2-byte length
	padding bool
	payload int
}

func (c *vmessChunkWriter) encodeSize(total int) []byte {
	var b [2]byte
	if c.size != nil {
		binary.BigEndian.PutUint16(b[:], c.size.encode(uint16(total)))
	} else {
		binary.BigEndian.PutUint16(b[:], uint16(total))
	}
	return b[:]
}

func (c *vmessChunkWriter) seal(data []byte) []byte {
	var padLen int
	if c.padding {
		padLen = int(c.size.nextPadding())
	}
	sealed := c.aead.Seal(nil, c.nonce(), data, nil)
	out := c.encodeSize(len(sealed) + padLen)
	out = append(out, sealed...)
	if padLen > 0 {
		out = append(out, make([]byte, padLen)...)
	}
	return out
}

func (c *vmessChunkWriter) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		n := len(p)
		if n > c.payload {
			n = c.payload
		}
		if _, err := c.w.Write(c.seal(p[:n])); err != nil {
			return 0, err
		}
		p = p[n:]
	}
	if total == 0 {
		if _, err := c.w.Write(c.seal(nil)); err != nil {
			return 0, err
		}
	}
	return total, nil
}

// end sends the terminating empty chunk.
func (c *vmessChunkWriter) end() error {
	_, err := c.w.Write(c.seal(nil))
	return err
}

// vmessChunkReader reads the authenticated chunk stream back into plaintext.
type vmessChunkReader struct {
	r       io.Reader
	aead    cipher.AEAD
	nonce   func() []byte
	size    *shakeSizeParser
	padding bool
	rem     []byte
	done    bool
}

func (c *vmessChunkReader) Read(p []byte) (int, error) {
	for len(c.rem) == 0 {
		if c.done {
			return 0, io.EOF
		}
		var sb [2]byte
		if _, err := io.ReadFull(c.r, sb[:]); err != nil {
			return 0, err
		}
		var padLen int
		if c.padding {
			padLen = int(c.size.nextPadding())
		}
		var total int
		if c.size != nil {
			total = int(c.size.decode(binary.BigEndian.Uint16(sb[:])))
		} else {
			total = int(binary.BigEndian.Uint16(sb[:]))
		}
		if total < c.aead.Overhead()+padLen {
			return 0, errors.New("vmess: short chunk")
		}
		if total == c.aead.Overhead()+padLen { // the end marker
			c.done = true
			return 0, io.EOF
		}
		chunk := make([]byte, total)
		if _, err := io.ReadFull(c.r, chunk); err != nil {
			return 0, err
		}
		plain, err := c.aead.Open(nil, c.nonce(), chunk[:total-padLen], nil)
		if err != nil {
			return 0, err
		}
		c.rem = plain
	}
	n := copy(p, c.rem)
	c.rem = c.rem[n:]
	return n, nil
}
