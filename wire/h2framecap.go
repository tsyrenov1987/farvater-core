package wire

import (
	"net"

	"golang.org/x/net/http2"
)

// h2FrameCap hides the server's SETTINGS_MAX_FRAME_SIZE from the Transport,
// which then keeps the spec's default of 16 KiB for the frames it sends.
//
// Go's Transport reads each request body through a scratch buffer as long as
// the server's frame size, up to 512 KiB, and holds it for the whole life of
// the stream (clientStream.writeRequestBody). An XHTTP or gRPC stream is one
// request whose body is the flow's upload, so behind Xray's 1 MiB frames every
// flow held 512 KiB, a silent one too: 180 idle app connections came to 88 MiB
// of the heap, while the iOS packet tunnel is killed near 50 MB. At 16 KiB the
// same buffer is a TLS record's worth, which is all one upload write carries
// anyway, and a browser sends DATA frames of that size whatever the server
// allows. Sending frames below the peer's maximum is always allowed, and a
// setting the Transport does not know it ignores (RFC 9113 §6.5.2), so the
// setting is renamed in place rather than cut out: one byte changes, no frame
// length does, and nothing the server sees.
type h2FrameCap struct {
	net.Conn
	hdr      [9]byte
	nhdr     int
	left     int  // payload bytes of the current frame still to come
	settings bool // the current frame is SETTINGS, not its ack
	off      int  // where the next byte falls in the SETTINGS payload
	prev     byte // the payload byte before it, across reads
}

// h2HiddenSetting is the identifier a server's MAX_FRAME_SIZE (0x0005) is
// read as: 0x00ff, which no HTTP/2 extension defines.
const h2HiddenSetting = 0xff

func (c *h2FrameCap) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	b := p[:n]
	for len(b) > 0 {
		if c.left == 0 && c.nhdr < 9 {
			k := copy(c.hdr[c.nhdr:], b)
			c.nhdr += k
			b = b[k:]
			if c.nhdr < 9 {
				break
			}
			c.left = int(c.hdr[0])<<16 | int(c.hdr[1])<<8 | int(c.hdr[2])
			c.settings = c.hdr[3] == h2FrameSettings && c.hdr[4]&h2FlagAck == 0
			c.off = 0
			if c.left == 0 {
				c.nhdr = 0
			}
			continue
		}
		k := min(c.left, len(b))
		if c.settings {
			// A setting is a 2-byte identifier and a 4-byte value; the
			// identifier's low byte decides, and it never splits.
			for i := range k {
				if (c.off+i)%6 == 1 && c.prev == 0 && b[i] == byte(http2.SettingMaxFrameSize) {
					b[i] = h2HiddenSetting
				}
				c.prev = b[i]
			}
			c.off += k
		}
		c.left -= k
		b = b[k:]
		if c.left == 0 {
			c.nhdr = 0
		}
	}
	return n, err
}
