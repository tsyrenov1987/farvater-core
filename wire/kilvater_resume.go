package wire

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tsyrenov1987/farvater-core/kilvater"
)

// KilvaterResume turns resumable flows on for the kilvater wire: a TCP flow
// names a session in its OPEN, and when its stream is lost (the path reset
// the connection, or froze it) the flow goes on over a new stream instead of
// ending (kilvater/resume.go). A server that does not know the option is
// served as before.
var KilvaterResume = true

// Timings of a resumption.
var (
	// kilResumeTry bounds one attempt to continue a flow on one path;
	// kilResumeTotal bounds them all, after which the flow ends with the
	// error that started them.
	kilResumeTry   = 4 * time.Second
	kilResumeTotal = 12 * time.Second
	// kilResumeProbe is how long a flow that has sent a whole window, and
	// heard nothing at all from the server, waits before it takes the server
	// for one that does not keep count.
	kilResumeProbe = 3 * time.Second
	// kilResumeRetry is how long a wire stops asking a server that did not
	// answer the option, before it asks again (the server may be upgraded
	// under a running client).
	kilResumeRetry = 10 * time.Minute
	// kilEndWait is how long a finished flow gives the server to take its
	// END before the stream is reset.
	kilEndWait = 500 * time.Millisecond
)

var kilResumed, kilResumeFailed atomic.Int64

// KilvaterResumeCounts reports how many times a flow went on over a new
// stream, and how many times it could not.
func KilvaterResumeCounts() (resumed, failed int64) {
	return kilResumed.Load(), kilResumeFailed.Load()
}

// kilPeers lists the live kilvater wires by key: wires with the same v2 key
// lead to the same node (the key is bound to it), so a flow that lost its
// stream on one may continue on another.
var kilPeers struct {
	mu sync.Mutex
	m  map[kilPeerKey][]*kilWire
}

type kilPeerKey struct {
	key kilvater.Key
	id  kilvater.KeyID
}

func (w *kilWire) peerKey() (kilPeerKey, bool) {
	if w.keyID == nil {
		return kilPeerKey{}, false // a v1 key is shared by every node
	}
	return kilPeerKey{w.key, *w.keyID}, true
}

func (w *kilWire) joinPeers() {
	k, ok := w.peerKey()
	if !ok {
		return
	}
	kilPeers.mu.Lock()
	if kilPeers.m == nil {
		kilPeers.m = map[kilPeerKey][]*kilWire{}
	}
	kilPeers.m[k] = append(kilPeers.m[k], w)
	kilPeers.mu.Unlock()
}

func (w *kilWire) leavePeers() {
	k, ok := w.peerKey()
	if !ok {
		return
	}
	kilPeers.mu.Lock()
	list := kilPeers.m[k]
	for i, p := range list {
		if p == w {
			list = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(kilPeers.m, k)
	} else {
		kilPeers.m[k] = list
	}
	kilPeers.mu.Unlock()
}

// resumePaths is where a flow of this wire may continue: the wire itself
// first, then the others that lead to the same node.
func (w *kilWire) resumePaths() []*kilWire {
	out := []*kilWire{w}
	if k, ok := w.peerKey(); ok {
		kilPeers.mu.Lock()
		for _, p := range kilPeers.m[k] {
			if p != w {
				out = append(out, p)
			}
		}
		kilPeers.mu.Unlock()
	}
	return out
}

// resumeWanted reports whether a new flow should ask for a session.
func (w *kilWire) resumeWanted() bool {
	if !KilvaterResume {
		return false
	}
	no := w.resumeNo.Load()
	return no == 0 || w.now().UnixNano()-no > int64(kilResumeRetry)
}

func (w *kilWire) noteResume(ok bool) {
	if ok {
		w.resumeNo.Store(0)
	} else {
		w.resumeNo.Store(w.now().UnixNano())
	}
}

// kilResume is one resumable flow on the client: the stream that carries it
// now, the bytes sent that the server has not confirmed, and the count of
// what has come back. It is the flow's writer, reader and closer for
// runStream; one goroutine writes and one reads.
type kilResume struct {
	w      *kilWire
	sid    kilvater.SessionID
	ctx    context.Context
	cancel context.CancelFunc

	mu         sync.Mutex
	cond       *sync.Cond
	st         net.Conn
	sh         *kilvater.Shaper
	gen        uint64
	up         kilvater.AckBuf
	taken      uint64 // DATA bytes received
	ackedDown  uint64 // the last count confirmed to the server
	peer       bool   // the server keeps count: an ACK has come
	off        bool   // the flow cannot be resumed (or no longer)
	recovering bool
	closed     bool
	probe      *time.Timer

	// the reader's own
	buf, rem []byte
	got      bool
	refused  bool
}

func newKilResume(w *kilWire, st net.Conn, sh *kilvater.Shaper) (*kilResume, error) {
	r := &kilResume{w: w, st: st, sh: sh}
	if _, err := crand.Read(r.sid[:]); err != nil {
		return nil, err
	}
	r.cond = sync.NewCond(&r.mu)
	r.ctx, r.cancel = context.WithCancel(context.Background())
	return r, nil
}

var errKilClosed = errors.New("kilvater: flow closed")

func (r *kilResume) Write(p []byte) (int, error) {
	r.mu.Lock()
	for {
		if r.closed {
			r.mu.Unlock()
			return 0, errKilClosed
		}
		if !r.recovering {
			if r.off || r.up.Len() == 0 || r.up.Len()+len(p) <= kilvater.ResumeWindow {
				break
			}
			if !r.peer && r.probe == nil {
				// A full window out and not a frame back: if this lasts, the
				// server is one that will never confirm anything.
				r.probe = time.AfterFunc(kilResumeProbe, r.giveUp)
			}
		}
		r.cond.Wait()
	}
	if !r.off {
		r.up.Append(p)
	}
	sh, gen := r.sh, r.gen
	r.mu.Unlock()
	if err := sh.WriteData(p); err != nil {
		if r.recover(gen) != nil {
			return 0, err
		}
		// p was held, and went out again with the rest on the new stream.
	}
	return len(p), nil
}

// giveUp stops keeping the sent bytes for a server that has said nothing.
func (r *kilResume) giveUp() {
	r.mu.Lock()
	if !r.peer && !r.off {
		r.unsupportedLocked()
	}
	r.mu.Unlock()
}

func (r *kilResume) unsupportedLocked() {
	r.off = true
	r.up.Reset()
	r.w.noteResume(false)
	r.cond.Broadcast()
}

func (r *kilResume) Read(p []byte) (int, error) {
	for len(r.rem) == 0 {
		r.mu.Lock()
		st, sh, gen := r.st, r.sh, r.gen
		r.mu.Unlock()
		typ, body, err := kilvater.ReadFrame(st, r.buf)
		if err != nil {
			if r.recover(gen) == nil {
				continue
			}
			return 0, err
		}
		r.buf = body[:0]
		switch typ {
		case kilvater.FrameData:
			r.mu.Lock()
			if !r.peer && !r.off {
				r.unsupportedLocked() // DATA before any ACK: an older server
			}
			r.taken += uint64(len(body))
			t, ack := r.taken, false
			if r.peer && t-r.ackedDown >= kilvater.ResumeAckStep {
				r.ackedDown, ack = t, true
			}
			r.mu.Unlock()
			if ack {
				sh.WriteFrame(kilvater.FrameAck, kilvater.AckBody(t))
			}
			r.rem = body
			r.got = true
		case kilvater.FrameAck:
			if off, ok := kilvater.ParseAck(body); ok {
				r.mu.Lock()
				if !r.peer {
					r.peer = true
					r.w.noteResume(true)
				}
				r.up.Ack(off)
				r.cond.Broadcast()
				r.mu.Unlock()
			}
		case kilvater.FrameClose:
			r.mu.Lock()
			if !r.peer && !r.off {
				r.unsupportedLocked()
			}
			r.mu.Unlock()
			if !r.got && len(body) > 0 && body[0] != kilvater.CloseOK {
				r.refused = true
			}
			return 0, io.EOF
		case kilvater.FramePad:
		default:
			if typ > kilvater.FrameClose {
				continue // a frame type from a newer server: skip it, like PAD
			}
			return 0, fmt.Errorf("kilvater: unexpected frame type %d", typ)
		}
	}
	n := copy(p, r.rem)
	r.rem = r.rem[n:]
	return n, nil
}

// Close ends the flow. A server that keeps the session is told so, or it
// would hold the target's connection for the client's return.
func (r *kilResume) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	if r.probe != nil {
		r.probe.Stop()
	}
	st, sh, tell := r.st, r.sh, r.peer && !r.recovering
	r.up.Reset()
	r.cancel()
	r.cond.Broadcast()
	r.mu.Unlock()
	if !tell {
		sh.Close()
		return st.Close()
	}
	// END, then the end of the request body: the server ends its side and the
	// reader sees the stream finish. The reset follows for a server, or a
	// path, that does not answer.
	time.AfterFunc(kilEndWait, func() { st.Close() })
	go func() {
		sh.WriteFrame(kilvater.FrameEnd, nil)
		sh.Close()
		if cw, ok := st.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()
	return nil
}

var errKilNoResume = errors.New("kilvater: the flow cannot be resumed")

// recover puts the flow on a new stream after the one of generation gen
// failed. The writer and the reader may both ask; one of them does the work
// and the other waits for it. nil means the flow goes on.
func (r *kilResume) recover(gen uint64) error {
	r.mu.Lock()
	for r.recovering && !r.closed {
		r.cond.Wait()
	}
	switch {
	case r.closed:
		r.mu.Unlock()
		return errKilClosed
	case r.gen != gen:
		r.mu.Unlock()
		return nil // the other side has done it already
	case !r.peer || r.off:
		r.mu.Unlock()
		return errKilNoResume
	}
	r.recovering = true
	oldSt, oldSh := r.st, r.sh
	r.mu.Unlock()
	oldSh.Close()
	oldSt.Close()

	err := r.reattach()

	r.mu.Lock()
	r.recovering = false
	if err != nil {
		r.off = true
		r.up.Reset()
		kilResumeFailed.Add(1)
	} else {
		kilResumed.Add(1)
	}
	r.cond.Broadcast()
	r.mu.Unlock()
	return err
}

// reattach tries the paths to the node, one after another, until the flow is
// on a new stream and what the server lacked has been sent again.
func (r *kilResume) reattach() error {
	ctx, cancel := context.WithTimeout(r.ctx, kilResumeTotal)
	defer cancel()
	err := errKilNoResume
	for _, w := range r.w.resumePaths() {
		if ctx.Err() != nil {
			break
		}
		if err = r.reattachOn(ctx, w); err == nil {
			return nil
		}
	}
	return err
}

func (r *kilResume) reattachOn(ctx context.Context, w *kilWire) error {
	ctx, cancel := context.WithTimeout(ctx, kilResumeTry)
	defer cancel()
	st, err := w.openTunnel(ctx)
	if err != nil {
		return err
	}
	// The stream ignores deadlines; closing it is what bounds the wait for
	// the server's answer.
	stop := context.AfterFunc(ctx, func() { st.Close() })
	sh := kilvater.NewShaper(st, r.w.pad)
	fail := func(err error) error {
		stop()
		sh.Close()
		st.Close()
		return err
	}

	r.mu.Lock()
	taken := r.taken
	r.mu.Unlock()
	head := kilvater.AppendFrame(nil, kilvater.FrameOpen, kilvater.AppendResume(nil, r.sid, taken))
	if err := sh.WriteOpening(head, nil); err != nil {
		return fail(err)
	}
	// The server answers with the count of our bytes it has, or with CLOSE.
	var from uint64
	for {
		typ, body, err := kilvater.ReadFrame(st, nil)
		if err != nil {
			return fail(err)
		}
		if typ == kilvater.FrameAck {
			off, ok := kilvater.ParseAck(body)
			if !ok {
				return fail(errKilNoResume)
			}
			from = off
			break
		}
		if typ <= kilvater.FrameClose && typ != kilvater.FramePad {
			return fail(errKilNoResume) // CLOSE: the session is not there
		}
	}

	r.mu.Lock()
	rest, ok := r.up.From(from)
	if !ok || r.closed {
		r.mu.Unlock()
		return fail(errKilNoResume)
	}
	again := append([]byte(nil), rest...) // before Ack, which moves the buffer
	r.up.Ack(from)
	r.st, r.sh = st, sh
	r.gen++
	r.mu.Unlock()
	if !stop() {
		// The attempt ran out as it succeeded: the stream is closed already.
		return fail(context.DeadlineExceeded)
	}
	// The writer waits while recovering is set, so nothing can get ahead of
	// the bytes sent again.
	if len(again) > 0 {
		if err := sh.WriteData(again); err != nil {
			return fail(err)
		}
	}
	return nil
}
