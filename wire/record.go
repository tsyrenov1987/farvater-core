package wire

import (
	"net"
	"sync"

	utls "github.com/refraction-networking/utls"
)

// Framed is a session that can tell a freeze of its own connection.
// InRecord reports whether the path's stream stopped inside one of its TLS
// records: the server writes each record whole, so the rest of it is held
// back on the way. A censor that freezes a connection cuts it at a TCP
// segment, which is almost never a record boundary of the path's TLS, while
// the app's TLS inside may well stop at one of its own: the app's framing
// alone does not show such a freeze.
type Framed interface {
	InRecord() bool
}

// recordConn is the path's TCP connection, its incoming TLS framing followed.
type recordConn struct {
	net.Conn
	mu sync.Mutex
	t  recordTrack
}

func (c *recordConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.t.feed(p[:n])
		c.mu.Unlock()
	}
	return n, err
}

func (c *recordConn) inRecord() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.t.off && (c.t.need > 0 || c.t.hn > 0)
}

// inRecord reports whether conn, a TLS or REALITY stream dialled by
// dialSecure, stopped inside a record. Other transports say no.
func inRecord(conn net.Conn) bool {
	if u, ok := conn.(*utls.UConn); ok {
		if r, ok := u.NetConn().(*recordConn); ok {
			return r.inRecord()
		}
	}
	return false
}

// recordTrack follows TLS record framing. The first header that does not
// parse switches it off.
type recordTrack struct {
	off  bool
	hdr  [5]byte
	hn   int // header bytes buffered
	need int // body bytes of the current record still to come
}

func (t *recordTrack) feed(p []byte) {
	for len(p) > 0 && !t.off {
		if t.need > 0 {
			k := min(t.need, len(p))
			t.need -= k
			p = p[k:]
			continue
		}
		k := copy(t.hdr[t.hn:], p)
		t.hn += k
		p = p[k:]
		if t.hn < len(t.hdr) {
			return
		}
		t.hn = 0
		typ, major, n := t.hdr[0], t.hdr[1], int(t.hdr[3])<<8|int(t.hdr[4])
		if typ < 20 || typ > 23 || major != 3 || n == 0 || n > 1<<14+2048 {
			t.off = true
			return
		}
		t.need = n
	}
}
