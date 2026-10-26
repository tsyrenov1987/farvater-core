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
