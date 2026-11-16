package kilvater

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// A resumable flow (docs/KILVATER.md, "Resuming a flow"). A TCP flow normally
// lives and dies with the HTTP/2 stream that carries it, so a connection the
// path resets takes every flow on it down. A client that puts a session id in
// its OPEN asks the server to keep the flow instead: both sides count the DATA
// bytes they have taken, keep what the other has not confirmed, and when the
// stream is lost the client opens a new one (on any path to the same node),
// names the session and the two pick up exactly where each stopped.
//
// Everything here is additive. A server that predates it ignores the bytes
// after the address in OPEN and the frame types it does not know; a client
// that predates it never sends them and is served as before.
const (
	FrameFlowAck byte = 10 // body: 8 bytes, how many DATA bytes the sender has taken
	FrameEnd     byte = 11 // body: empty; the client is done with the flow, keep nothing

	// NetResume opens a stream that continues a session: the OPEN body is
	// [NetResume][sid:16][8 bytes: DATA bytes the client has taken].
	NetResume byte = 3

	// CloseGone answers a NetResume the server cannot continue (no such
	// session, or it no longer holds the bytes the client lacks).
	CloseGone byte = 3

	// OpenExtSession is the option, after the address in OPEN, that carries
	// the session id: [OpenExtSession][16][sid:16].
	OpenExtSession byte = 1

	// ResumeAckStep is how many bytes a side takes before it confirms them.
	// A sender's window must be several steps, or it waits on a confirmation
	// the receiver is not yet due to send. A quarter of the window: every
	// confirmation is a short record against the flow, and at 64 KiB a
	// download of 8 MiB sent ~130 of them where a browser's WINDOW_UPDATEs
	// come to ~10 (docs/KILVATER.md §8). The step is the receiver's alone, so
	// a peer on either step works with one on the other.
	ResumeAckStep = 256 << 10
	// ResumeWindow is how many unconfirmed bytes a side holds per direction
	// before it stops sending.
	ResumeWindow = 1 << 20
)

// SessionID names a resumable flow. It is random and travels only inside TLS.
type SessionID [SessionIDLen]byte

// AppendSessionExt appends the session option to an OPEN body that ends with
// the address.
func AppendSessionExt(b []byte, sid SessionID) []byte {
	b = append(b, OpenExtSession, SessionIDLen)
	return append(b, sid[:]...)
}

// ParseSessionExt reads the options after the address in OPEN and returns the
// session id, if one is there. Options it does not know are skipped.
func ParseSessionExt(rest []byte) (SessionID, bool) {
	var sid SessionID
	for len(rest) >= 2 {
		typ, n := rest[0], int(rest[1])
		if len(rest) < 2+n {
			break
		}
		if typ == OpenExtSession && n == SessionIDLen {
			copy(sid[:], rest[2:2+n])
			return sid, true
		}
		rest = rest[2+n:]
	}
	return sid, false
}

// AppendResume makes the OPEN body of a stream that continues a session.
func AppendResume(b []byte, sid SessionID, taken uint64) []byte {
	b = append(b, NetResume)
	b = append(b, sid[:]...)
	return binary.BigEndian.AppendUint64(b, taken)
}

// AckBody is the body of an ACK frame.
func AckBody(taken uint64) []byte {
	return binary.BigEndian.AppendUint64(make([]byte, 0, 8), taken)
}

// ParseAck reads an ACK body.
func ParseAck(body []byte) (uint64, bool) {
	if len(body) < 8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(body), true
}

// held counts the bytes every AckBuf in the process holds: the apps write it
// into their last-breath record, to tell resume's memory from the rest.
var held atomic.Int64

// Held is the total of bytes held unconfirmed by all AckBufs in the process.
func Held() int64 { return held.Load() }

// AckBuf holds the bytes one side has sent and the other has not confirmed:
// the stream from offset Base on. It is not safe for concurrent use.
type AckBuf struct {
	base uint64
	data []byte
}

// Base is the offset of the first byte held; End is one past the last.
func (b *AckBuf) Base() uint64 { return b.base }
func (b *AckBuf) End() uint64  { return b.base + uint64(len(b.data)) }
func (b *AckBuf) Len() int     { return len(b.data) }

// Append adds p at End.
func (b *AckBuf) Append(p []byte) {
	b.data = append(b.data, p...)
	held.Add(int64(len(p)))
}

// Ack drops everything before off. An offset outside what is held is ignored
// and reported.
func (b *AckBuf) Ack(off uint64) bool {
	if off < b.base || off > b.End() {
		return false
	}
	n := int(off - b.base)
	b.base = off
	held.Add(-int64(n))
	if n == len(b.data) {
		b.data = b.data[:0]
		if cap(b.data) > 256<<10 {
			b.data = nil // a burst is over: give the memory back
		}
		return true
	}
	// Move the rest down, so the slice does not creep along its array.
	b.data = b.data[:copy(b.data, b.data[n:])]
	return true
}

// From returns the bytes held from off on (not a copy), or false if off is
// outside what is held.
func (b *AckBuf) From(off uint64) ([]byte, bool) {
	if off < b.base || off > b.End() {
		return nil, false
	}
	return b.data[off-b.base:], true
}

// Reset empties the buffer and frees its memory.
func (b *AckBuf) Reset() {
	held.Add(-int64(len(b.data)))
	b.base, b.data = b.End(), nil
}

// WriteFrame writes one frame of any type through the shaper's lock, so it
// never lands inside another frame the shaper is writing.
func (s *Shaper) WriteFrame(typ byte, body []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return WriteFrame(s.w, typ, body)
}

// writeAckPad writes an ACK and a PAD in one Write, so the ACK that opens a
// stream is not a record of one fixed size.
func writeAckPad(w io.Writer, taken uint64) error {
	var n [1]byte
	rand.Read(n[:])
	b := AppendFrame(make([]byte, 0, 300), FrameFlowAck, AckBody(taken))
	b = AppendFrame(b, FramePad, make([]byte, 16+int(n[0])))
	_, err := w.Write(b)
	return err
}

// Resume defaults (Server.ResumeGrace and friends).
const (
	DefaultResumeGrace    = 30 * time.Second
	DefaultResumeMaxBytes = 128 << 20
	DefaultResumeMaxKept  = 4096
)

type sessKey struct {
	label string
	sid   SessionID
}

// sessions is the server's table of resumable flows.
type sessions struct {
	mu sync.Mutex
	m  map[sessKey]*session

	held atomic.Int64 // bytes buffered for clients, all sessions
	kept atomic.Int64 // sessions waiting, with no stream, for a client to return

	keys map[string]*keyUse // per key label, under mu

	resumed, gone, lost atomic.Int64
}

// keyUse is what one key's sessions hold, for the per-key caps.
type keyUse struct {
	held atomic.Int64
	kept atomic.Int64
	n    int // sessions, under sessions.mu
}

// heldAdd and keptAdd count for the whole table and for the session's key.
func (se *session) heldAdd(n int64) {
	se.tab.held.Add(n)
	se.use.held.Add(n)
}

func (se *session) keptAdd(n int64) {
	se.tab.kept.Add(n)
	se.use.kept.Add(n)
}

// keyBudgetWait is how often a flow held back by its key's budget looks again:
// the confirmations that free the budget arrive on the key's other flows.
var keyBudgetWait = 20 * time.Millisecond

// session is one resumable TCP flow: the connection to the target, and the
// bytes from it the client has not confirmed. It outlives the streams that
// carry it; at most one stream is attached at a time, and the latest wins.
type session struct {
	tab    *sessions
	key    sessKey
	remote net.Conn
	window int
	use    *keyUse
	budget int64 // the key's ResumeMaxBytesPerKey; 0 is none

	mu      sync.Mutex
	cond    *sync.Cond
	down    AckBuf // read from the target, not yet confirmed by the client
	downEOF bool   // the target finished (or failed): nothing more will come
	gen     uint64 // which attachment is current; 0 is none yet
	on      bool   // a stream is attached
	closed  bool
	timer   *time.Timer

	// upMu orders writes to the target with a change of attachment, so a
	// stream that has been replaced can never write after its successor.
	upMu  sync.Mutex
	upGen uint64
	up    uint64 // DATA bytes taken for the target (written or queued)

	// The client's bytes reach the target through a queue and a writer of
	// their own, so a target that is slow to read never stops the stream's
	// frame loop: FLOWACKs behind the DATA are still read, the target's
	// answer still flows down, and the two sides cannot wait on each other.
	// The client keeps at most a window unconfirmed, and the server confirms
	// only what the target has taken (written), never what is merely queued,
	// so the queue stays within that window; qMax is only a guard against a
	// peer that does not (FV-007: confirming queued bytes let an upload fill
	// the queue to qMax while the target was busy writing its answer, and the
	// frame loop then waited on the target, which waited on the frame loop).
	qMu     sync.Mutex
	qCond   *sync.Cond
	q       [][]byte // nil entry: the client finished sending (half-close)
	qLen    int
	qMax    int
	qDead   bool
	written uint64 // DATA bytes the target has taken; counts like up
}

func (t *sessions) add(key sessKey, remote net.Conn, window int, budget int64) *session {
	se := &session{tab: t, key: key, remote: remote, window: window, budget: budget}
	se.cond = sync.NewCond(&se.mu)
	se.qCond = sync.NewCond(&se.qMu)
	se.qMax = 2*window + 256<<10
	t.mu.Lock()
	if t.m == nil {
		t.m = map[sessKey]*session{}
	}
	if t.keys == nil {
		t.keys = map[string]*keyUse{}
	}
	if se.use = t.keys[key.label]; se.use == nil {
		se.use = &keyUse{}
		t.keys[key.label] = se.use
	}
	se.use.n++
	old := t.m[key]
	t.m[key] = se
	t.mu.Unlock()
	if old != nil {
		old.close() // a session id used twice: the earlier flow is over
	}
	go se.readRemote()
	go se.writeRemote()
	return se
}

// writeRemote gives the queued client bytes to the target in order. A failed
// write ends the session: the target is gone and nothing can come back to it.
func (se *session) writeRemote() {
	for {
		se.qMu.Lock()
		for !se.qDead && len(se.q) == 0 {
			se.qCond.Wait()
		}
		if se.qDead {
			se.qMu.Unlock()
			return
		}
		p := se.q[0]
		se.q[0] = nil
		se.q = se.q[1:]
		se.qMu.Unlock()
		if p == nil {
			closeWrite(se.remote) // the client finished sending; the target may go on
			continue
		}
		n, err := se.remote.Write(p)
		se.qMu.Lock()
		se.qLen -= len(p)
		se.written += uint64(n)
		se.qCond.Broadcast()
		se.qMu.Unlock()
		if err != nil {
			se.close()
			return
		}
	}
}

// enqueue puts p (nil: half-close) in the target's queue, waiting while the
// queue is over its guard. It fails once the session is over.
func (se *session) enqueue(p []byte) error {
	se.qMu.Lock()
	defer se.qMu.Unlock()
	for !se.qDead && p != nil && se.qLen > 0 && se.qLen+len(p) > se.qMax {
		se.qCond.Wait()
	}
	if se.qDead {
		return errSessionGone
	}
	se.q = append(se.q, p)
	se.qLen += len(p)
	se.qCond.Broadcast()
	return nil
}

func (t *sessions) get(key sessKey) *session {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.m[key]
}

// readRemote moves the target's bytes into the buffer for as long as the
// session lives, attached or not, and stops while the buffer is full: the
// target is then held back by TCP, as it would be by a slow client.
func (se *session) readRemote() {
	p := make([]byte, 32<<10)
	for {
		se.mu.Lock()
		for !se.closed && se.down.Len() >= se.window {
			se.cond.Wait()
		}
		closed := se.closed
		// Past the key's budget a flow that already holds something waits
		// for confirmations; one that holds nothing may still read, so the
		// key's flows can never all stand still.
		over := se.budget > 0 && se.down.Len() > 0 && se.use.held.Load() >= se.budget
		se.mu.Unlock()
		if closed {
			return
		}
		if over {
			time.Sleep(keyBudgetWait)
			continue
		}
		n, err := se.remote.Read(p)
		se.mu.Lock()
		if se.closed {
			se.mu.Unlock()
			return
		}
		if n > 0 {
			se.down.Append(p[:n])
			se.heldAdd(int64(n))
		}
		if err != nil {
			se.downEOF = true
		}
		se.cond.Broadcast()
		se.mu.Unlock()
		if err != nil {
			return
		}
	}
}

// close ends the session: the target's connection, and everything held.
func (se *session) close() {
	se.mu.Lock()
	if se.closed {
		se.mu.Unlock()
		return
	}
	se.closed = true
	if se.timer != nil {
		se.timer.Stop()
	}
	if !se.on && se.gen != 0 {
		se.keptAdd(-1)
	}
	se.heldAdd(-int64(se.down.Len()))
	se.down.Reset()
	se.cond.Broadcast()
	se.mu.Unlock()
	se.qMu.Lock()
	se.qDead = true
	se.q = nil
	se.qCond.Broadcast()
	se.qMu.Unlock()
	se.remote.Close()
	se.tab.mu.Lock()
	if se.tab.m[se.key] == se {
		delete(se.tab.m, se.key)
	}
	if se.use.n--; se.use.n == 0 && se.tab.keys[se.key.label] == se.use {
		delete(se.tab.keys, se.key.label)
	}
	se.tab.mu.Unlock()
}

var errSessionGone = errors.New("kilvater: session gone")

// attach makes a new stream the session's current one. from is the offset the
// client has taken the target's bytes up to. It returns the attachment's
// generation and how many of the client's bytes the target has been given.
func (se *session) attach(from uint64) (gen, up uint64, err error) {
	se.upMu.Lock()
	defer se.upMu.Unlock()
	se.mu.Lock()
	defer se.mu.Unlock()
	if se.closed {
		return 0, 0, errSessionGone
	}
	if _, ok := se.down.From(from); !ok {
		return 0, 0, errSessionGone
	}
	se.ackLocked(from)
	if se.timer != nil {
		se.timer.Stop()
		se.timer = nil
	}
	if !se.on && se.gen != 0 {
		se.keptAdd(-1)
	}
	se.gen++
	se.on = true
	se.upGen = se.gen
	se.cond.Broadcast() // the stream this one replaces stops writing
	return se.gen, se.up, nil
}

func (se *session) ackLocked(off uint64) {
	before := se.down.Len()
	if se.down.Ack(off) {
		se.heldAdd(int64(se.down.Len() - before))
		se.cond.Broadcast()
	}
}

// ack records that the client has taken the target's bytes up to off.
func (se *session) ack(off uint64) {
	se.mu.Lock()
	se.ackLocked(off)
	se.mu.Unlock()
}

// writeUp takes the client's bytes for the target, unless the stream they came
// on has been replaced. It returns the new count. The bytes are queued, not
// written here (see writeRemote): the session owns them from now on, and a
// resumed stream continues after them.
func (se *session) writeUp(gen uint64, p []byte) (uint64, error) {
	se.upMu.Lock()
	defer se.upMu.Unlock()
	if se.upGen != gen {
		return 0, errSessionGone
	}
	if err := se.enqueue(append([]byte(nil), p...)); err != nil {
		return 0, err
	}
	se.up += uint64(len(p))
	return se.up, nil
}

// closeUp passes the client's half-close to the target after its queued bytes.
func (se *session) closeUp(gen uint64) {
	se.upMu.Lock()
	defer se.upMu.Unlock()
	if se.upGen == gen {
		se.enqueue(nil)
	}
}

// detach is the end of a stream that did not end the flow. The session waits
// grace for the client to come back on another stream, unless the server
// already keeps as much as it may, in which case the flow ends as it would
// have without resumption.
func (se *session) detach(gen uint64, grace time.Duration, maxKept, maxBytes, maxKeptPerKey int64) {
	se.mu.Lock()
	if se.closed || se.gen != gen {
		se.mu.Unlock()
		return
	}
	if grace <= 0 || se.tab.kept.Load() >= maxKept || se.tab.held.Load() >= maxBytes ||
		(maxKeptPerKey > 0 && se.use.kept.Load() >= maxKeptPerKey) {
		se.mu.Unlock()
		se.tab.lost.Add(1)
		se.close()
		return
	}
	se.on = false
	se.keptAdd(1)
	se.timer = time.AfterFunc(grace, func() {
		se.mu.Lock()
		stale := se.closed || se.on || se.gen != gen
		se.mu.Unlock()
		if !stale {
			se.tab.lost.Add(1)
			se.close()
		}
	})
	se.cond.Broadcast()
	se.mu.Unlock()
}

// serve carries the session over one stream until the stream or the flow
// ends. sent is where the client's copy of the target's bytes stops.
func (s *Server) serve(se *session, gen, sent uint64, upDone uint64, up io.Reader, down io.Writer, ks *keyStat) {
	sh := NewShaper(down, s.Pad)
	defer sh.Close()
	// The first frame tells the client the flow is resumable and, on a
	// resumed stream, where to send from.
	if err := writeAckPad(down, upDone); err != nil {
		se.detach(gen, s.resumeGrace(), s.resumeMaxKept(), s.resumeMaxBytes(), s.ResumeMaxKeptPerKey)
		return
	}

	stop := make(chan struct{}) // closed when the upstream side is done
	wdone := make(chan struct{})
	go func() {
		defer close(wdone)
		var chunk []byte
		for {
			se.mu.Lock()
			for {
				if se.closed || se.gen != gen {
					se.mu.Unlock()
					return
				}
				select {
				case <-stop:
					se.mu.Unlock()
					return
				default:
				}
				if sent < se.down.End() || se.downEOF {
					break
				}
				se.cond.Wait()
			}
			rest, ok := se.down.From(sent)
			if !ok {
				se.mu.Unlock()
				return
			}
			if len(rest) == 0 { // downEOF, and the client has been sent it all
				se.mu.Unlock()
				sh.Close() // stop idle PAD so CLOSE is the last frame
				WriteFrame(down, FrameClose, []byte{CloseOK})
				return
			}
			if len(rest) > 32<<10 {
				rest = rest[:32<<10]
			}
			chunk = append(chunk[:0], rest...)
			se.mu.Unlock()
			if err := sh.WriteData(chunk); err != nil {
				return
			}
			sent += uint64(len(chunk))
			ks.addDown(len(chunk))
		}
	}()

	// The client's bytes are confirmed as the target takes them, not as
	// they arrive: a FLOWACK frees the client's window, and a window freed
	// for bytes still queued would let the queue outgrow it (FV-007).
	adone := make(chan struct{})
	go func() {
		defer close(adone)
		acked := upDone
		for {
			se.qMu.Lock()
			for {
				if se.qDead {
					se.qMu.Unlock()
					return
				}
				select {
				case <-stop:
					se.qMu.Unlock()
					return
				default:
				}
				if se.written > acked && se.written-acked >= ResumeAckStep {
					break
				}
				se.qCond.Wait()
			}
			n := se.written
			se.qMu.Unlock()
			if err := sh.WriteFrame(FrameFlowAck, AckBody(n)); err != nil {
				return
			}
			acked = n
		}
	}()

	ended := false // the client said the flow is over
	var buf []byte
loop:
	for {
		typ, body, err := ReadFrame(up, buf)
		if err != nil {
			break
		}
		buf = body[:0]
		switch typ {
		case FrameData:
			if _, err := se.writeUp(gen, body); err != nil {
				if !errors.Is(err, errSessionGone) {
					ended = true // the target is gone: nothing to come back to
				}
				break loop
			}
			ks.addUp(len(body))
		case FrameFlowAck:
			if off, ok := ParseAck(body); ok {
				se.ack(off)
			}
		case FrameEnd:
			ended = true
			break loop
		case FrameClose:
			se.closeUp(gen) // after the queued bytes; the target may go on
		default:
			// PAD, and any type a newer client may send
		}
	}

	if ended {
		se.close()
	}
	close(stop)
	se.mu.Lock()
	se.cond.Broadcast()
	se.mu.Unlock()
	se.qMu.Lock()
	se.qCond.Broadcast()
	se.qMu.Unlock()
	<-wdone
	<-adone
	if !ended {
		se.detach(gen, s.resumeGrace(), s.resumeMaxKept(), s.resumeMaxBytes(), s.ResumeMaxKeptPerKey)
	}
}

func (s *Server) resumeGrace() time.Duration {
	return s.ResumeGrace
}

func (s *Server) resumeMaxKept() int64 {
	if s.ResumeMaxKept > 0 {
		return s.ResumeMaxKept
	}
	return DefaultResumeMaxKept
}

func (s *Server) resumeMaxBytes() int64 {
	if s.ResumeMaxBytes > 0 {
		return s.ResumeMaxBytes
	}
	return DefaultResumeMaxBytes
}

func (s *Server) resumeWindow() int {
	if s.ResumeWindow >= 4*ResumeAckStep {
		return s.ResumeWindow
	}
	return ResumeWindow
}

// ResumeStats is what the session table has done and holds now.
type ResumeStats struct {
	Resumed, Gone, Lost int64 // streams that continued a flow; that asked for one the server no longer had; flows dropped while waiting
	Kept, HeldBytes     int64 // flows waiting for their client now; bytes buffered for clients now
}

// ResumeStats reports the session table's counters.
func (s *Server) ResumeStats() ResumeStats {
	t := &s.sess
	return ResumeStats{t.resumed.Load(), t.gone.Load(), t.lost.Load(), t.kept.Load(), t.held.Load()}
}
