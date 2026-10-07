package kilvater

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// Server is an HTTP handler that distinguishes tunnel clients from ordinary
// visitors by the _sid cookie. A valid cookie begins a framed tunnel session
// over the HTTP/2 stream; everything else gets the Decoy page, so a probe or
// a browser sees an ordinary website.
type Server struct {
	Verifier *Verifier
	Decoy    http.Handler
	Logger   *log.Logger
}

// openReadTimeout bounds how long the server waits for a client's OPEN frame
// after it has authenticated, so a client that never opens cannot hold a stream.
var openReadTimeout = 15 * time.Second

func (s *Server) log(format string, args ...any) {
	if s.Logger != nil {
		s.Logger.Printf(format, args...)
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(CookieName)
	if err != nil || s.Verifier.Verify(c.Value, r.URL.Path, time.Now()) < 0 {
		s.Decoy.ServeHTTP(w, r)
		return
	}
	s.tunnel(w, r)
}

func (s *Server) tunnel(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	down := &flushed{w: w, f: fl}
	WritePad(down) // vary the size of the first record the client sees

	// Read the OPEN frame, but never let a client that authenticated yet never
	// opens hold the stream: bound the wait. Returning resets the stream, which
	// unblocks the read goroutine.
	type opened struct {
		typ  byte
		body []byte
		err  error
	}
	ch := make(chan opened, 1)
	go func() {
		var buf []byte
		typ, body, err := ReadFrame(r.Body, buf)
		ch <- opened{typ, body, err}
	}()
	var f opened
	select {
	case f = <-ch:
	case <-time.After(openReadTimeout):
		return
	case <-r.Context().Done():
		return
	}
	if f.err != nil || f.typ != FrameOpen || len(f.body) < 2 {
		return
	}
	addr, _, err := ParseAddr(f.body[1:])
	if err != nil {
		return
	}

	switch f.body[0] {
	case NetTCP:
		s.tcp(r.Context(), addr, r.Body, down)
	default:
		WriteFrame(down, FrameClose, []byte{1})
	}
}

func (s *Server) tcp(ctx context.Context, addr string, up io.Reader, down io.Writer) {
	remote, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		s.log("dial %s: %v", addr, err)
		WriteFrame(down, FrameClose, []byte{1})
		return
	}
	defer remote.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// When the stream goes away (client reset, or the request context ended),
	// close the remote so the downstream reader cannot block on it forever.
	go func() {
		<-ctx.Done()
		remote.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer closeWrite(remote)
		var buf []byte
		for {
			typ, body, err := ReadFrame(up, buf)
			if err != nil {
				cancel()
				return
			}
			buf = body[:0]
			switch typ {
			case FrameData:
				if _, err := remote.Write(body); err != nil {
					cancel()
					return
				}
			case FramePad:
			case FrameClose:
				return
			default:
				cancel()
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		p := make([]byte, 32*1024)
		for {
			n, err := remote.Read(p)
			if n > 0 {
				chunk := p[:n]
				for len(chunk) > 0 {
					sz := len(chunk)
					if sz > MaxFrame {
						sz = MaxFrame
					}
					if werr := WriteFrame(down, FrameData, chunk[:sz]); werr != nil {
						cancel()
						return
					}
					chunk = chunk[sz:]
				}
			}
			if err != nil {
				WriteFrame(down, FrameClose, []byte{0})
				cancel()
				return
			}
		}
	}()

	wg.Wait()
}

func closeWrite(c net.Conn) {
	type halfCloser interface{ CloseWrite() error }
	if hc, ok := c.(halfCloser); ok {
		hc.CloseWrite()
	}
}

type flushed struct {
	w http.ResponseWriter
	f http.Flusher
}

func (fw *flushed) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	fw.f.Flush()
	return n, err
}
