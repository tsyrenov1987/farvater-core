package wire

import "sync"

// The fixed per-flow buffers (the read buffer of each pump, the first-payload
// read) come from a pool rather than a fresh allocation per flow: a phone opens
// hundreds of flows a minute, and garbage is what keeps the Go heap pressed
// against the tunnel's memory limit, the collector running and the battery
// draining. A buffer goes back only once nothing refers to it; what is handed
// on (a chunk sent up a channel, a prelude) is copied out first.
const poolBufSize = 32 << 10

var bufPool = sync.Pool{New: func() any { b := make([]byte, poolBufSize); return &b }}

// GetBuf returns a pooled buffer of poolBufSize bytes; give it back with PutBuf.
func GetBuf() *[]byte { return bufPool.Get().(*[]byte) }

// PutBuf returns a buffer from GetBuf to the pool.
func PutBuf(b *[]byte) {
	if b != nil && cap(*b) == poolBufSize {
		*b = (*b)[:poolBufSize]
		bufPool.Put(b)
	}
}

// smallBufSize is what a flow reads into while it carries little or nothing.
const smallBufSize = 4 << 10

var smallPool = sync.Pool{New: func() any { b := make([]byte, smallBufSize); return &b }}

// FlexBuf is a pump's read buffer that is big only while data pours. Most of a
// phone's flows sit idle most of their life (keep-alive, push, a page already
// loaded), each blocked in Read on its buffer: with two 32 KiB buffers a flow,
// 160 flows held 10.5 MB of the iOS tunnel's heap (heap profile, 16.11), close
// to a third of it, and a burst of new flows took the tunnel past jetsam's
// limit. A FlexBuf reads into 4 KiB; a read that fills it moves to the big
// buffer, and a read that comes back with less than 4 KiB (the data ran dry,
// the next Read will wait) gives the big buffer back.
//
// Buf's slice is valid until the next Done: callers write or copy out what
// they read before reading again, as the pumps do.
type FlexBuf struct {
	small, big *[]byte
	max        int // the most one read may take (≤ poolBufSize)
}

// NewFlexBuf returns a FlexBuf whose big reads take at most max bytes.
func NewFlexBuf(max int) *FlexBuf {
	if max <= 0 || max > poolBufSize {
		max = poolBufSize
	}
	return &FlexBuf{small: smallPool.Get().(*[]byte), max: max}
}

// Buf is the slice to read into now.
func (b *FlexBuf) Buf() []byte {
	if b.big != nil {
		return (*b.big)[:b.max]
	}
	return (*b.small)[:smallBufSize]
}

// Done tells the buffer how much the last read into Buf returned.
func (b *FlexBuf) Done(n int) {
	switch {
	case b.big == nil && n >= smallBufSize && b.max > smallBufSize:
		b.big = GetBuf()
	case b.big != nil && n < smallBufSize:
		PutBuf(b.big)
		b.big = nil
	}
}

// Release gives both buffers back; the FlexBuf is not used after.
func (b *FlexBuf) Release() {
	if b.big != nil {
		PutBuf(b.big)
		b.big = nil
	}
	if b.small != nil {
		smallPool.Put(b.small)
		b.small = nil
	}
}
