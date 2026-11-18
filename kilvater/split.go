package kilvater

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The split transport carries a tunnel stream as separate HTTP requests, the
// way XHTTP's packet-up does, so that it passes through a CDN that will not
// stream a request body (Yandex Cloud CDN allows no POST without asking its
// support, and buffers what it does allow):
//
//	GET <base>/<sid>/d          the downlink: one long streamed response
//	GET <base>/<sid>/u/<seq>    the uplink, a piece per request, carried in
//	                            the X-Sd-0..X-Sd-N headers (base64url)
//	POST <base>/<sid>/u/<seq>   the same piece in the body, where POST passes
//
// sid is the session id, 16 random bytes in base64url (22 characters); seq
// counts the uplink pieces from 0. Every request carries its own tag over its
// own path, so a request with a stolen sid but no key goes to the decoy like
// any other. The streams in both directions are sealed (seal.go): a CDN ends
// TLS and would otherwise see the frames, the OPEN frame's target with them.
//
// A piece with the X-Sd-Fin header ends the uplink after it: the server's
// reader gets EOF, as on a POST stream whose body ended.

const (
	SplitSIDLen    = 22 // base64url of 16 bytes
	SplitHeader    = "X-Sd-"
	SplitFinHeader = "X-Sd-Fin"

	// How long a session waits for its downlink, or for the next uplink piece
	// while the downlink is gone, before it is dropped.
	splitIdle = 30 * time.Second
	// The most uplink bytes a session holds out of order (a piece ahead of one
	// that has not arrived yet). Past it the session is broken.
	splitMaxPending = 4 << 20
	// The downlink sends a PAD after this much quiet, so a CDN or proxy that
	// drops idle responses does not cut the stream. Yandex Cloud CDN kept a
	// response through 40 s of quiet and cut it at 70 s (measured 18.11).
	splitKeepalive = 15 * time.Second
)

var errSplitPending = errors.New("kilvater: split uplink too far ahead")

type splitKind int

const (
	splitNone splitKind = iota
	splitDown
	splitUp
)

// parseSplitPath reads a split request's path: the sid and, for an uplink
// piece, its number.
func parseSplitPath(p string) (kind splitKind, sid string, seq uint64) {
	parts := strings.Split(p, "/")
	n := len(parts)
	switch {
	case n >= 3 && parts[n-1] == "d" && len(parts[n-2]) == SplitSIDLen:
		return splitDown, parts[n-2], 0
	case n >= 4 && parts[n-2] == "u" && len(parts[n-3]) == SplitSIDLen:
		q, err := strconv.ParseUint(parts[n-1], 10, 32)
		if err != nil {
			return splitNone, "", 0
		}
		return splitUp, parts[n-3], q
	}
	return splitNone, "", 0
}

type splitSess struct {
	label string
	key   Key
	sid   []byte

	mu      sync.Mutex
	next    uint64
	pend    map[uint64][]byte
	pending int
	finAt   int64 // the piece after which the uplink ends; -1 none yet
	downOn  bool
	last    time.Time
	err     error

	wmu sync.Mutex // one writer to pw at a time, in order
	pr  *io.PipeReader
	pw  *io.PipeWriter
}

type splitTable struct {
	mu sync.Mutex
	m  map[string]*splitSess
}

func (t *splitTable) get(sid string, id Identity, now time.Time) (*splitSess, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[string]*splitSess{}
	}
	if s, ok := t.m[sid]; ok {
		// A session belongs to the key that opened it: another key's tag on
		// the same sid is refused, not joined.
		return s, s.label == id.Label() && s.key == id.Key()
	}
	raw, err := base64.RawURLEncoding.DecodeString(sid)
	if err != nil {
		return nil, false
	}
	pr, pw := io.Pipe()
	s := &splitSess{label: id.Label(), key: id.Key(), sid: raw, pend: map[uint64][]byte{}, finAt: -1, last: now, pr: pr, pw: pw}
	t.m[sid] = s
	go t.reap(sid, s)
	return s, true
}

// reap drops a session that has had no downlink, or no uplink piece while
// the downlink is gone, for splitIdle.
func (t *splitTable) reap(sid string, s *splitSess) {
	tk := time.NewTicker(splitIdle / 3)
	defer tk.Stop()
	for range tk.C {
		s.mu.Lock()
		idle := !s.downOn && time.Since(s.last) > splitIdle
		dead := s.err != nil && !s.downOn
		s.mu.Unlock()
		if idle || dead {
			t.drop(sid, s, io.ErrClosedPipe)
			return
		}
	}
}

func (t *splitTable) drop(sid string, s *splitSess, err error) {
	t.mu.Lock()
	if t.m[sid] == s {
		delete(t.m, sid)
	}
	t.mu.Unlock()
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
	s.pw.CloseWithError(err)
	s.pr.CloseWithError(err)
}

// put takes an uplink piece and writes every piece now in order to the pipe.
// The write blocks until the tunnel reads it, so a fast uploader is held at
// the speed of the target, and the piece's response waits with it.
func (s *splitSess) put(seq uint64, data []byte, fin bool) error {
	s.mu.Lock()
	s.last = time.Now()
	if s.err != nil {
		s.mu.Unlock()
		return s.err
	}
	if seq >= s.next {
		if _, dup := s.pend[seq]; !dup {
			s.pend[seq] = data
			s.pending += len(data)
		}
		if fin {
			s.finAt = int64(seq)
		}
	}
	if s.pending > splitMaxPending {
		s.mu.Unlock()
		return errSplitPending
	}
	s.mu.Unlock()

	s.wmu.Lock()
	defer s.wmu.Unlock()
	for {
		s.mu.Lock()
		d, ok := s.pend[s.next]
		if !ok {
			s.mu.Unlock()
			return nil
		}
		delete(s.pend, s.next)
		s.pending -= len(d)
		end := s.finAt == int64(s.next)
		s.next++
		s.mu.Unlock()
		if len(d) > 0 {
			if _, err := s.pw.Write(d); err != nil {
				return err
			}
		}
		if end {
			s.pw.Close()
			return nil
		}
	}
}

// serveSplit handles an admitted split request (ServeHTTP has verified its
// tag and parsed its path).
func (s *Server) serveSplit(w http.ResponseWriter, r *http.Request, id Identity, kind splitKind, sid string, seq uint64) {
	ss, ok := s.split.get(sid, id, time.Now())
	if !ok {
		s.Decoy.ServeHTTP(w, r)
		return
	}
	switch kind {
	case splitUp:
		data, fin, err := splitPiece(r)
		if err == nil {
			err = ss.put(seq, data, fin)
		}
		if err != nil {
			s.split.drop(sid, ss, err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	case splitDown:
		ss.mu.Lock()
		taken := ss.downOn
		ss.downOn = true
		ss.mu.Unlock()
		if taken {
			s.Decoy.ServeHTTP(w, r) // one downlink per session
			return
		}
		ks, ok := s.admit(id, time.Now())
		if !ok {
			s.Metrics.limitReject()
			s.split.drop(sid, ss, io.ErrClosedPipe)
			s.Decoy.ServeHTTP(w, r)
			return
		}
		defer s.Metrics.closeStream(ks)
		defer s.split.drop(sid, ss, io.EOF)
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		h := w.Header()
		h.Set("Content-Type", "text/event-stream")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		fl.Flush()
		ka := newKeepalive(NewSealWriter(&flushed{w: w, f: fl}, ss.key, ss.sid, SealDown), splitKeepalive)
		defer ka.stop()
		up := io.NopCloser(NewSealReader(ss.pr, ss.key, ss.sid, SealUp))
		s.frames(r.Context(), r.Host, ss.label, &splitUpReader{Reader: up, ss: ss}, ka, ks)
	}
}

// splitUpReader closes the session's pipe when the tunnel is done with it.
type splitUpReader struct {
	io.Reader
	ss *splitSess
}

func (u *splitUpReader) Close() error { return u.ss.pr.Close() }

// splitPiece reads an uplink piece: the request body for a POST, else the
// X-Sd-0..N headers in order.
func splitPiece(r *http.Request) ([]byte, bool, error) {
	fin := r.Header.Get(SplitFinHeader) != ""
	if r.Method == http.MethodPost {
		b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
		if err == nil && len(b) > 1<<20 {
			err = errSplitPending
		}
		return b, fin, err
	}
	var out []byte
	for i := 0; ; i++ {
		v := r.Header.Get(SplitHeader + strconv.Itoa(i))
		if v == "" {
			return out, fin, nil
		}
		b, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			return nil, false, err
		}
		out = append(out, b...)
	}
}

// keepalive writes a PAD frame through w after every quiet spell of d, and
// serialises the writes so a PAD never lands inside another frame.
type keepalive struct {
	mu   sync.Mutex
	w    io.Writer
	last time.Time
	done chan struct{}
}

func newKeepalive(w io.Writer, d time.Duration) *keepalive {
	k := &keepalive{w: w, last: time.Now(), done: make(chan struct{})}
	go func() {
		t := time.NewTicker(d / 3)
		defer t.Stop()
		for {
			select {
			case <-k.done:
				return
			case <-t.C:
				k.mu.Lock()
				if time.Since(k.last) >= d {
					WritePad(k.w)
					k.last = time.Now()
				}
				k.mu.Unlock()
			}
		}
	}()
	return k
}

func (k *keepalive) Write(p []byte) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.last = time.Now()
	return k.w.Write(p)
}

func (k *keepalive) stop() { close(k.done) }
