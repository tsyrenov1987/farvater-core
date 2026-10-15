package kilvater

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"syscall"
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

	// AllowPrivate lets clients reach loopback, private, link-local and
	// other non-public addresses. Off by default: a key holder must not be
	// able to talk to the server's own local services or its LAN.
	AllowPrivate bool

	// Pad is how the server shapes the record sizes and timing it sends
	// downstream (PadMode). The zero value is PadModerate. It is one-sided:
	// an old client reads any mode the same way.
	Pad PadMode

	// Metrics, if set, counts traffic and health per key. nil disables it.
	Metrics *Metrics

	// MaxBytesPerKey caps the total (up+down) payload bytes one key may carry
	// before its new streams are refused; MaxStreamsPerKey caps a key's
	// concurrent streams. Both are off at zero, and both need Metrics set. A
	// refused request gets the decoy, like a bad tag; a stream already running
	// is never cut.
	MaxBytesPerKey   int64
	MaxStreamsPerKey int64

	// Dial, if set, reaches the clients' TCP targets instead of the checked
	// dialer (a test lab routing every name to its own site).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

var errForbiddenTarget = errors.New("kilvater: target address not allowed")

// cgnat is the shared address space of RFC 6598, which netip does not
// classify as private.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// publicOnly reports whether ip may be dialed when AllowPrivate is off.
func publicOnly(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsValid() && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsUnspecified() &&
		!ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsInterfaceLocalMulticast() &&
		!ip.IsMulticast() && !cgnat.Contains(ip)
}

// dialer checks the address actually dialed, after name resolution, so a
// hostname that resolves to a private address is refused too.
func (s *Server) dialer() *net.Dialer {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if !s.AllowPrivate {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !publicOnly(ap.Addr()) {
				return errForbiddenTarget
			}
			return nil
		}
	}
	return d
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
	if err != nil {
		s.Decoy.ServeHTTP(w, r) // an ordinary visitor, no tag at all
		return
	}
	n, id := s.Verifier.VerifyIdentity(c.Value, r.URL.Path, time.Now())
	if n < 0 {
		s.Metrics.authFail() // a tag cookie was present but did not verify
		s.Decoy.ServeHTTP(w, r)
		return
	}
	if s.overLimit(id) {
		s.Metrics.limitReject()
		s.Decoy.ServeHTTP(w, r)
		return
	}
	s.tunnel(w, r, id)
}

// overLimit reports whether a key has reached a configured per-key limit, so
// its next stream is refused. It never cuts a running stream.
func (s *Server) overLimit(id Identity) bool {
	if s.Metrics == nil || (s.MaxBytesPerKey <= 0 && s.MaxStreamsPerKey <= 0) {
		return false
	}
	ks := s.Metrics.stat(id.Label())
	if s.MaxBytesPerKey > 0 && ks.up.Load()+ks.down.Load() >= s.MaxBytesPerKey {
		return true
	}
	if s.MaxStreamsPerKey > 0 && ks.streamsOpen.Load() >= s.MaxStreamsPerKey {
		return true
	}
	return false
}

func (s *Server) tunnel(w http.ResponseWriter, r *http.Request, id Identity) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	ks := s.Metrics.openStream(id.Label())
	defer s.Metrics.closeStream(ks)
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
		s.Metrics.openTimeout()
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
		s.tcp(r.Context(), addr, r.Body, down, ks)
	case NetUDP:
		s.udp(r.Context(), addr, r.Body, down, ks)
	default:
		WriteFrame(down, FrameClose, []byte{1})
	}
}

func (s *Server) tcp(ctx context.Context, addr string, up io.Reader, down io.Writer, ks *keyStat) {
	dial := s.dialer().DialContext
	if s.Dial != nil {
		dial = s.Dial
	}
	remote, err := dial(ctx, "tcp", addr)
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

	// The downstream direction is shaped: DATA is split into a web-like spread
	// of sizes instead of a run of 16 KiB records, with PAD mixed in (shape.go).
	sh := NewShaper(down, s.Pad)
	defer sh.Close()

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
				ks.addUp(len(body))
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
				if werr := sh.WriteData(p[:n]); werr != nil {
					cancel()
					return
				}
				ks.addDown(n)
			}
			if err != nil {
				sh.Close() // stop idle PAD so CLOSE is the last frame
				WriteFrame(down, FrameClose, []byte{0})
				cancel()
				return
			}
		}
	}()

	wg.Wait()
}

// udpAssocIdle ends a UDP association the server has heard nothing on, either
// way, for this long, so an association whose client vanished frees its socket.
var udpAssocIdle = 2 * time.Minute

// udp carries one UDP association. OPEN names a single target (NetUDP), and a
// connected UDP socket to it does double duty: it binds the association to that
// one target (one stream = one association) and gives UDP the very same
// public-address check as TCP, since s.dialer's Control runs on the resolved
// address here too. Each datagram is its own frame, so message boundaries are
// kept across the tunnel; the shaper, which reshapes a byte stream, is not used.
func (s *Server) udp(ctx context.Context, addr string, up io.Reader, down io.Writer, ks *keyStat) {
	remote, err := s.dialer().DialContext(ctx, "udp", addr)
	if err != nil {
		s.log("dial udp %s: %v", addr, err)
		WriteFrame(down, FrameClose, []byte{1})
		return
	}
	defer remote.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// When the association ends from either side, close the socket so the
	// reader below cannot block on it forever.
	go func() {
		<-ctx.Done()
		remote.Close()
	}()

	// Reclaim an association that has gone quiet both ways; reset on traffic.
	idle := time.AfterFunc(udpAssocIdle, cancel)
	defer idle.Stop()

	var wg sync.WaitGroup
	wg.Add(2)

	// Up: one datagram frame from the client is one datagram to the target.
	go func() {
		defer wg.Done()
		var buf []byte
		for {
			typ, body, err := ReadFrame(up, buf)
			if err != nil {
				cancel()
				return
			}
			buf = body[:0]
			switch typ {
			case FrameDgram:
				idle.Reset(udpAssocIdle)
				if _, err := remote.Write(body); err != nil {
					cancel()
					return
				}
				ks.addUp(len(body))
			case FramePad:
			case FrameClose:
				cancel() // UDP has no half-close: end both ways
				return
			default:
				cancel()
				return
			}
		}
	}()

	// Down: each datagram from the target is one frame back. A datagram too
	// large to frame is dropped here, as any UDP datagram may be dropped.
	go func() {
		defer wg.Done()
		p := make([]byte, 64<<10) // read a whole datagram so none is truncated
		for {
			n, err := remote.Read(p)
			if n > 0 {
				idle.Reset(udpAssocIdle)
				if n <= MaxFrame {
					if werr := WriteFrame(down, FrameDgram, p[:n]); werr != nil {
						cancel()
						return
					}
					ks.addDown(n)
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
