package wire

import (
	"io"
	"sync"
)

// h2Body is a request body that gathers what is written to it, where io.Pipe
// hands each write over on its own. The http2 Transport makes one DATA frame
// of each Read and flushes it, so with io.Pipe every write of the tunnel is a
// TLS record of its own size. Here a Read takes all that has been written
// since the last one, up to piece bytes: while the connection is the slower
// side, writes pile up and the frames come out full, as a browser's do when it
// uploads a file; a lone small write still leaves at once, nothing waits on a
// timer. piece is 9 bytes short of a TLS record so the frame and its header
// fill exactly one.
type h2Body struct {
	mu    sync.Mutex
	cond  sync.Cond
	buf   []byte
	piece int
	werr  error // set by the writer's Close: what Read returns once buf is empty
	rerr  error // set by the reader's Close: what Write returns
}

const (
	h2BodyPiece = 16384 - 9
	h2BodyHold  = 4 * 16384 // a writer waits once this much is unread
)

func newH2Body(piece int) *h2Body {
	b := &h2Body{piece: piece}
	b.cond.L = &b.mu
	return b
}

func (b *h2Body) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for len(p) > 0 {
		for len(b.buf) >= h2BodyHold && b.rerr == nil && b.werr == nil {
			b.cond.Wait()
		}
		if b.rerr != nil {
			return n, b.rerr
		}
		if b.werr != nil {
			return n, io.ErrClosedPipe
		}
		k := min(len(p), h2BodyHold-len(b.buf))
		b.buf = append(b.buf, p[:k]...)
		p, n = p[k:], n+k
		b.cond.Broadcast()
	}
	return n, nil
}

// Close ends the body: the reader gets what is left and then io.EOF.
func (b *h2Body) Close() error { return b.CloseWithError(nil) }

func (b *h2Body) CloseWithError(err error) error {
	if err == nil {
		err = io.EOF
	}
	b.mu.Lock()
	if b.werr == nil {
		b.werr = err
	}
	b.cond.Broadcast()
	b.mu.Unlock()
	return nil
}

// h2BodyReader is the end the Transport holds; its Close is the Transport
// saying the stream is over.
type h2BodyReader struct{ b *h2Body }

func (r h2BodyReader) Read(p []byte) (int, error) {
	b := r.b
	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.buf) == 0 && b.werr == nil && b.rerr == nil {
		b.cond.Wait()
	}
	if b.rerr != nil {
		return 0, b.rerr
	}
	if len(b.buf) == 0 {
		return 0, b.werr
	}
	n := copy(p[:min(len(p), b.piece)], b.buf)
	b.buf = b.buf[:copy(b.buf, b.buf[n:])]
	b.cond.Broadcast()
	return n, nil
}

func (r h2BodyReader) Close() error {
	b := r.b
	b.mu.Lock()
	if b.rerr == nil {
		b.rerr = io.ErrClosedPipe
	}
	b.cond.Broadcast()
	b.mu.Unlock()
	return nil
}
