package kilvater

import (
	"encoding/binary"
	"errors"
	"io"
	"sort"
	"sync"
	"time"
)

// A bond carries one TCP flow over several tunnel streams ("legs") at once,
// each through its own route to the same server: one through a CDN relay in
// the country, one through VK's call relays, and so on. Neither route alone is
// fast enough on a whitelisted mobile network; together they add up. Every leg
// is an ordinary kilvater stream; its first frame is JOIN instead of OPEN.
//
// The byte stream each way is cut into chunks, each sent as SEQ with its
// offset. A leg takes the next chunk when it has room (pull scheduling), so a
// fast leg carries more. The receiver puts chunks back in order and answers
// with ACK: how far it has received in order (the sender forgets everything
// below) and how far the far end has read (the window). A chunk on a leg that
// died is sent again on another; a chunk holding up the order for too long is
// sent again on a second leg (hedging), and the copy that arrives last is
// dropped. FIN gives the final offset of a direction.
//
// An ACK may also carry [leg]: how many payload bytes of SEQ the far end has
// read off the leg the ACK travels on. With it the sender knows what each leg
// itself delivered, whatever is still missing in between, so it measures each
// route's own speed and delay, keeps no more on a route than it needs, and
// sees at once a route that stopped delivering. An end that does not send it
// is served the old way, by the in-order point alone.
//
// Frames (after the 4-byte frame header):
//
//	JOIN  [session id 16][flags 1][network 1][addr]  first frame of a leg
//	SEQ   [offset 8][payload]
//	ACK   [received in order 8][read 8]([leg 8])
//	FIN   [final offset 8]
//	CLOSE [code 1]  0: the bond is done; else it failed
//
// A server that knows no bonds drops a stream whose first frame is not OPEN,
// so against it a bond simply fails and the client uses its other paths.
const (
	FrameJoin byte = 6
	FrameSeq  byte = 7
	FrameAck  byte = 8
	FrameFin  byte = 9
)

// JoinCreate in a JOIN's flags lets the leg start the bond when the server
// has none under its id. A leg that rejoins a running bond leaves it unset, so
// a server that lost the bond (a restart) refuses it instead of starting the
// flow over from the middle.
const JoinCreate byte = 1

// SessionIDLen is the length of a bond's id.
const SessionIDLen = 16

var (
	errBondClosed = errors.New("kilvater: bond closed")
	// ErrBondFailed is the far end ending the bond with an error.
	ErrBondFailed = errors.New("kilvater: bond failed at the far end")
)

// Tuning. A var so tests can shrink the times.
var (
	bondWindow     = 1 << 20      // unread bytes one side may have in flight
	bondChunk      = MaxFrame - 8 // payload of one SEQ
	bondHedgeAfter = 400 * time.Millisecond
	bondTick       = 20 * time.Millisecond
	bondRateEvery  = 250 * time.Millisecond
	bondLegCapMin  = 64 << 10
	bondLegCapInit = 256 << 10
	bondLegQueue   = 600 * time.Millisecond // a leg's cap is this much of its delivery rate
	bondAckEvery   = 32 << 10
	bondCloseGrace = 2 * time.Second
	// A leg whose oldest chunk holds up the flow for this long (or for twice
	// its usual delay, if that is longer) is taken to have stalled: everything
	// on it goes out on the others and it rests, longer each time it stalls.
	bondStallMin  = 700 * time.Millisecond
	bondRestFirst = time.Second
	bondRestMax   = 8 * time.Second
	bondRestProbe = 300 * time.Millisecond
)

type bondChunkT struct {
	body     []byte // [offset 8][payload]: the SEQ body as sent
	off      uint64
	n        int
	leg      *bondLeg // the leg it was last given to (its bytes count there); nil when queued again
	hedgedAt time.Time
	sentAt   time.Time // when it was last given to a leg
	got      bool      // the far end has it (said by a leg's count)
}

func (c *bondChunkT) end() uint64 { return c.off + uint64(c.n) }

type bondLeg struct {
	rw       io.ReadWriteCloser
	inflight int
	cap      int
	acked    int // bytes released on this leg since the last rate update
	busy     bool
	rate     float64 // bytes per second, smoothed
	ackDue   bool
	finSent  bool
	dead     bool
	accepted bool // the far end answered on it
	done     chan struct{}
	delay    time.Duration // smoothed time from a chunk going out to the far end having it in order
	restTill time.Time     // a stalled leg takes no chunks until then
	rest     time.Duration // how long it rested last; 0 once it delivers again

	// per-leg counts (see ACK [leg])
	sent      uint64 // payload bytes of SEQ given to this leg
	rcvd      uint64 // payload bytes of SEQ read off this leg
	rcvdAcked uint64 // rcvd as last told the far end
	peerGot   uint64 // the far end's rcvd for this leg
	counts    bool   // the far end sends [leg]
	marks     []legMark
	minRTT    time.Duration
	restAt    time.Time // when it last began to rest
	probeAt   time.Time // a resting leg's last probe
}

// legMark is a chunk given to a leg, and where it ends in the leg's count.
type legMark struct {
	end uint64
	at  time.Time
	c   *bondChunkT
	n   int
}

// Bond is one end of a bonded flow. Write sends, Read receives in order,
// CloseWrite ends the sending direction, Close ends the bond. Legs are added
// with RunLeg at any time; the flow lives on while one does.
type Bond struct {
	mu   sync.Mutex
	cond *sync.Cond
	legs map[*bondLeg]struct{}

	ackNoLeg bool // tests: ACK as an end without [leg] does

	// sending
	pending  []*bondChunkT // never sent
	unacked  []*bondChunkT // sent, not yet received in order by the far end; offset order
	retx     []*bondChunkT // of unacked: to send again (their leg died); offset order
	nextOff  uint64
	peerRcv  uint64 // the far end has everything below
	peerRead uint64 // the far end's reader has taken everything below
	progress time.Time
	finSet   bool
	finOff   uint64

	// receiving
	rcvNext    uint64
	ooo        map[uint64][]byte
	oooBytes   int
	ready      [][]byte
	read       uint64
	peerFinSet bool
	peerFin    uint64
	ackRcv     uint64 // what the last ACK said
	ackRead    uint64
	lastRx     *bondLeg
	ackForce   bool

	closed    bool
	closeCode byte
	err       error
	quit      chan struct{}
	now       func() time.Time
}

// NewBond makes one end of a bond.
func NewBond() *Bond {
	b := &Bond{legs: map[*bondLeg]struct{}{}, ooo: map[uint64][]byte{}, quit: make(chan struct{}), now: time.Now}
	b.cond = sync.NewCond(&b.mu)
	b.progress = b.now()
	go b.ticker()
	return b
}

// AppendJoin makes a JOIN body.
func AppendJoin(b []byte, id [SessionIDLen]byte, flags, network byte, addr string) ([]byte, error) {
	b = append(b, id[:]...)
	b = append(b, flags, network)
	return AppendAddr(b, addr)
}

// ParseJoin reads a JOIN body.
func ParseJoin(body []byte) (id [SessionIDLen]byte, flags, network byte, addr string, err error) {
	if len(body) < SessionIDLen+3 {
		return id, 0, 0, "", errors.New("kilvater: bad join")
	}
	copy(id[:], body)
	flags, network = body[SessionIDLen], body[SessionIDLen+1]
	addr, _, err = ParseAddr(body[SessionIDLen+2:])
	return id, flags, network, addr, err
}

// Write queues p to send; it blocks while the far end has a window's worth
// unread.
func (b *Bond) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for len(p) > 0 {
		for !b.closed && !b.finSet && b.nextOff-b.peerRead >= uint64(bondWindow) {
			b.cond.Wait()
		}
		if b.closed {
			return n, b.closedErr()
		}
		if b.finSet {
			return n, errBondClosed
		}
		k := len(p)
		if k > bondChunk {
			k = bondChunk
		}
		if room := int(uint64(bondWindow) - (b.nextOff - b.peerRead)); k > room {
			k = room
		}
		body := make([]byte, 8+k)
		binary.BigEndian.PutUint64(body, b.nextOff)
		copy(body[8:], p[:k])
		b.pending = append(b.pending, &bondChunkT{body: body, off: b.nextOff, n: k})
		b.nextOff += uint64(k)
		p = p[k:]
		n += k
		b.cond.Broadcast()
	}
	return n, nil
}

// CloseWrite ends the sending direction once what was written is out.
func (b *Bond) CloseWrite() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.finSet {
		b.finSet, b.finOff = true, b.nextOff
		b.cond.Broadcast()
	}
	return nil
}

// Read returns the far end's bytes in order; io.EOF once its FIN is reached.
func (b *Bond) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.ready) == 0 {
		if b.peerFinSet && b.read >= b.peerFin {
			return 0, io.EOF
		}
		if b.closed {
			if b.err != nil {
				return 0, b.err
			}
			return 0, io.EOF
		}
		b.cond.Wait()
	}
	n := copy(p, b.ready[0])
	if n == len(b.ready[0]) {
		b.ready[0] = nil
		b.ready = b.ready[1:]
	} else {
		b.ready[0] = b.ready[0][n:]
	}
	b.read += uint64(n)
	if b.read-b.ackRead >= uint64(bondWindow/4) {
		b.ackForce = true // the window opened: say so before the tick
		b.wantAckLocked()
	}
	return n, nil
}

// Drain waits until the far end has received everything sent up to FIN, or
// the timeout, or the bond ends.
func (b *Bond) Drain(timeout time.Duration) bool {
	t := time.AfterFunc(timeout, func() { b.mu.Lock(); b.cond.Broadcast(); b.mu.Unlock() })
	defer t.Stop()
	deadline := b.now().Add(timeout)
	b.mu.Lock()
	defer b.mu.Unlock()
	for !(b.finSet && b.peerRcv >= b.finOff) {
		if b.closed || !b.now().Before(deadline) {
			return false
		}
		b.cond.Wait()
	}
	return true
}

// Close ends the bond: the far end is told (CLOSE 0) and the legs close.
func (b *Bond) Close() error { b.shut(0, nil); return nil }

// Abort ends the bond with an error code for the far end.
func (b *Bond) Abort(code byte, err error) { b.shut(code, err) }

// Done reports whether the bond has ended.
func (b *Bond) Done() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

// Legs is the number of live legs.
func (b *Bond) Legs() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.legs)
}

func (b *Bond) shut(code byte, err error) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed, b.closeCode, b.err = true, code, err
	close(b.quit)
	legs := make([]*bondLeg, 0, len(b.legs))
	for l := range b.legs {
		legs = append(legs, l)
	}
	b.cond.Broadcast()
	b.mu.Unlock()
	// The writers send CLOSE and close their legs; a leg stuck in a write is
	// closed under it after a grace.
	time.AfterFunc(bondCloseGrace, func() {
		for _, l := range legs {
			l.rw.Close()
		}
	})
}

func (b *Bond) closedErr() error {
	if b.err != nil {
		return b.err
	}
	return errBondClosed
}

// RunLeg carries the bond over rw until the leg fails or the bond ends. The
// JOIN (client) or its answer (server) has already been exchanged by the
// caller; accept makes this end answer at once with an ACK, which is how a
// server tells the client the leg is in. It reports whether the far end ever
// answered on the leg.
func (b *Bond) RunLeg(rw io.ReadWriteCloser, accept bool) bool {
	l := &bondLeg{rw: rw, cap: bondLegCapInit, ackDue: accept, done: make(chan struct{})}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		rw.Close()
		return false
	}
	b.legs[l] = struct{}{}
	b.cond.Broadcast()
	b.mu.Unlock()
	wdone := make(chan struct{})
	go func() { b.writer(l); close(wdone) }()
	b.reader(l)
	<-wdone
	b.mu.Lock()
	defer b.mu.Unlock()
	return l.accepted
}

// legDead takes a leg out: its chunks go back to be sent on the others.
func (b *Bond) legDeadLocked(l *bondLeg) {
	if l.dead {
		return
	}
	l.dead = true
	delete(b.legs, l)
	l.inflight = 0
	l.marks = nil
	for _, c := range b.unacked {
		if c.leg == l {
			c.leg = nil
			if !c.got {
				b.retx = append(b.retx, c)
			}
		}
	}
	sort.Slice(b.retx, func(i, j int) bool { return b.retx[i].off < b.retx[j].off })
	if b.lastRx == l {
		b.lastRx = nil
	}
	b.cond.Broadcast()
}

func (b *Bond) reader(l *bondLeg) {
	defer func() {
		b.mu.Lock()
		b.legDeadLocked(l)
		b.mu.Unlock()
		l.rw.Close()
	}()
	var buf []byte
	for {
		typ, body, err := ReadFrame(l.rw, buf)
		if err != nil {
			return
		}
		buf = body[:0]
		switch typ {
		case FrameSeq:
			if len(body) < 9 {
				return
			}
			b.recv(l, binary.BigEndian.Uint64(body), body[8:])
		case FrameAck:
			if len(body) < 16 {
				return
			}
			b.ack(l, binary.BigEndian.Uint64(body), binary.BigEndian.Uint64(body[8:]))
			if len(body) >= 24 {
				b.legAck(l, binary.BigEndian.Uint64(body[16:]))
			}
		case FrameFin:
			if len(body) < 8 {
				return
			}
			b.mu.Lock()
			l.accepted = true
			if !b.peerFinSet {
				b.peerFinSet, b.peerFin = true, binary.BigEndian.Uint64(body)
				b.ackForce = true
				b.lastRx = l
				b.wantAckLocked()
			}
			b.mu.Unlock()
		case FramePad:
		case FrameClose:
			code := byte(1)
			if len(body) > 0 {
				code = body[0]
			}
			if code == 0 {
				b.shut(0, nil)
			} else {
				b.shut(code, ErrBondFailed)
			}
			return
		default:
			return
		}
	}
}

func (b *Bond) recv(l *bondLeg, off uint64, data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	l.accepted = true
	l.rcvd += uint64(len(data))
	if l.rcvd-l.rcvdAcked >= uint64(bondAckEvery) {
		l.ackDue = true
		b.cond.Broadcast()
	}
	b.lastRx = l
	end := off + uint64(len(data))
	if end <= b.rcvNext || len(data) == 0 {
		return // a copy of what we have
	}
	if off < b.rcvNext || end > b.read+uint64(bondWindow)+uint64(bondChunk) {
		return // not on a chunk boundary we know, or past the window: drop
	}
	if _, dup := b.ooo[off]; dup {
		return
	}
	b.ooo[off] = append([]byte(nil), data...)
	b.oooBytes += len(data)
	for {
		c, ok := b.ooo[b.rcvNext]
		if !ok {
			break
		}
		delete(b.ooo, b.rcvNext)
		b.oooBytes -= len(c)
		b.ready = append(b.ready, c)
		b.rcvNext += uint64(len(c))
	}
	if b.rcvNext-b.ackRcv >= uint64(bondAckEvery) {
		l.ackDue = true
	}
	b.cond.Broadcast()
}

func (b *Bond) ack(l *bondLeg, rcv, read uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	l.accepted = true
	if rcv > b.nextOff {
		rcv = b.nextOff
	}
	if read > rcv {
		read = rcv
	}
	if read > b.peerRead {
		b.peerRead = read
	}
	if rcv <= b.peerRcv {
		b.cond.Broadcast()
		return
	}
	b.peerRcv = rcv
	b.progress = b.now()
	i := 0
	for ; i < len(b.unacked) && b.unacked[i].end() <= rcv; i++ {
		c := b.unacked[i]
		c.got = true
		if c.leg != nil {
			l := c.leg
			c.leg = nil
			l.inflight -= c.n
			if l.counts {
				continue // its own count already said
			}
			l.acked += c.n
			if d := b.progress.Sub(c.sentAt); l.delay == 0 {
				l.delay = d
			} else {
				l.delay = (7*l.delay + d) / 8
			}
			if l.rest > 0 && !b.progress.Before(l.restTill) {
				l.rest = 0 // it delivers again
			}
		}
		b.unacked[i] = nil
	}
	b.unacked = b.unacked[i:]
	j := 0
	for ; j < len(b.retx) && b.retx[j].end() <= rcv; j++ {
	}
	b.retx = b.retx[j:]
	b.cond.Broadcast()
}

// legAck takes the far end's count for leg l: the chunks it brought are had,
// and each gives a sample of the leg's own delay.
func (b *Bond) legAck(l *bondLeg, got uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	l.counts = true
	if got > l.sent {
		got = l.sent
	}
	if got <= l.peerGot {
		return
	}
	l.peerGot = got
	now := b.now()
	i, back := 0, false
	for ; i < len(l.marks) && l.marks[i].end <= got; i++ {
		m := l.marks[i]
		l.acked += m.n
		back = back || !m.at.Before(l.restAt)           // sent since the rest began, and got through
		if d := now.Sub(m.at); !m.at.Before(l.restAt) { // what sat through a stall says nothing of the leg's delay
			if l.delay == 0 {
				l.delay = d
			} else {
				l.delay = (7*l.delay + d) / 8
			}
			if l.minRTT == 0 || d < l.minRTT {
				l.minRTT = d
			}
		}
		if c := m.c; !c.got {
			c.got = true
			if c.leg != nil {
				c.leg.inflight -= c.n
				c.leg = nil
			}
		}
		l.marks[i] = legMark{}
	}
	l.marks = l.marks[i:]
	if back && l.rest > 0 {
		l.rest, l.restTill = 0, now
	}
	b.cond.Broadcast()
}

// room is how much more the leg may take now.
func (l *bondLeg) room() int {
	if l.counts {
		return l.cap - int(l.sent-l.peerGot)
	}
	return l.cap - l.inflight
}

// wantAckLocked marks a leg to carry an ACK: the one that last brought data,
// else any.
func (b *Bond) wantAckLocked() {
	if b.lastRx != nil && !b.lastRx.dead {
		b.lastRx.ackDue = true
	} else {
		for l := range b.legs {
			l.ackDue = true
			break
		}
	}
	b.cond.Broadcast()
}

// pickLocked finds the next chunk for a leg with room: one to send again, the
// head held up too long (sent on a second leg), or a new one.
func (b *Bond) pickLocked(l *bondLeg, now time.Time) *bondChunkT {
	if now.Before(l.restTill) {
		// Resting: once per rest, a little in, it carries a copy of the head,
		// which ends the rest as soon as it gets through. One only: whatever
		// a stalled route holds is delivered first, and more would only add
		// to that.
		if l.counts && len(b.unacked) > 0 && l.probeAt.Before(l.restAt) && now.Sub(l.restAt) >= bondRestProbe {
			if h := b.unacked[0]; !h.got && h.leg != l {
				l.probeAt = now
				l.mark(h, now)
				return h
			}
		}
		return nil
	}
	if l.room() <= 0 {
		return nil
	}
	for len(b.retx) > 0 && b.retx[0].got {
		b.retx = b.retx[1:]
	}
	if len(b.retx) > 0 {
		c := b.retx[0]
		b.retx = b.retx[1:]
		c.leg, c.sentAt = l, now
		l.inflight += c.n
		l.mark(c, now)
		return c
	}
	if len(b.unacked) > 0 && len(b.legs) > 1 {
		h := b.unacked[0]
		if h.leg != l && !h.got && now.Sub(b.progress) >= bondHedgeAfter && now.Sub(h.hedgedAt) >= bondHedgeAfter {
			h.hedgedAt = now
			l.mark(h, now)
			return h
		}
	}
	if len(b.pending) > 0 {
		c := b.pending[0]
		b.pending[0] = nil
		b.pending = b.pending[1:]
		c.leg, c.sentAt = l, now
		l.inflight += c.n
		l.mark(c, now)
		b.unacked = append(b.unacked, c)
		return c
	}
	return nil
}

func (l *bondLeg) mark(c *bondChunkT, now time.Time) {
	l.sent += uint64(c.n)
	l.marks = append(l.marks, legMark{end: l.sent, at: now, c: c, n: c.n})
}

func (b *Bond) writer(l *bondLeg) {
	defer l.rw.Close()
	var ackBody [24]byte
	var finBody [8]byte
	for {
		b.mu.Lock()
		var typ byte
		var body []byte
		for {
			if l.dead {
				b.mu.Unlock()
				return
			}
			if b.closed {
				code := b.closeCode
				b.mu.Unlock()
				WriteFrame(l.rw, FrameClose, []byte{code})
				return
			}
			if l.ackDue {
				l.ackDue = false
				b.ackRcv, b.ackRead = b.rcvNext, b.read
				binary.BigEndian.PutUint64(ackBody[:], b.rcvNext)
				binary.BigEndian.PutUint64(ackBody[8:], b.read)
				binary.BigEndian.PutUint64(ackBody[16:], l.rcvd)
				l.rcvdAcked = l.rcvd
				typ, body = FrameAck, ackBody[:]
				if b.ackNoLeg {
					body = ackBody[:16]
				}
				break
			}
			if c := b.pickLocked(l, b.now()); c != nil {
				l.busy = true
				typ, body = FrameSeq, c.body
				break
			}
			if b.finSet && !l.finSent && len(b.pending) == 0 && len(b.retx) == 0 {
				l.finSent = true
				binary.BigEndian.PutUint64(finBody[:], b.finOff)
				typ, body = FrameFin, finBody[:]
				break
			}
			b.cond.Wait()
		}
		b.mu.Unlock()
		if err := WriteFrame(l.rw, typ, body); err != nil {
			b.mu.Lock()
			b.legDeadLocked(l)
			b.mu.Unlock()
			return
		}
	}
}

// stallCheckLocked rests the leg that holds the head of the flow up for far
// longer than it usually takes, and sends what it carries on the others. A
// leg that merely hiccups would otherwise give the chunks back one at a time,
// each after the hedge wait, and the whole flow would crawl at that pace.
func (b *Bond) stallCheckLocked(now time.Time) {
	for l := range b.legs {
		if !l.counts || len(l.marks) == 0 || now.Before(l.restTill) {
			continue
		}
		limit := bondStallMin
		if d := 2*l.delay + 200*time.Millisecond; d > limit {
			limit = d
		}
		since := l.marks[0].at
		if since.Before(l.restTill) {
			since = l.restTill // what it held before its rest is judged from the rest's end
		}
		if now.Sub(since) >= limit {
			b.restLocked(l, now)
		}
	}
	if len(b.unacked) == 0 || now.Sub(b.progress) < bondHedgeAfter {
		return
	}
	l := b.unacked[0].leg
	if l == nil || l.dead || l.counts {
		return
	}
	limit := bondStallMin
	if d := 2 * l.delay; d > limit {
		limit = d
	}
	if now.Sub(b.unacked[0].sentAt) < limit {
		return
	}
	b.restLocked(l, now)
	b.progress = now // give the others a full wait before judging them
}

// restLocked rests a stalled leg and queues what it holds for the others,
// unless there are no others to take it.
func (b *Bond) restLocked(l *bondLeg, now time.Time) {
	other := false
	for o := range b.legs {
		if o != l && !now.Before(o.restTill) {
			other = true
			break
		}
	}
	if !other {
		return // nowhere better to send it
	}
	if l.rest == 0 {
		l.rest = bondRestFirst
	} else if l.rest *= 2; l.rest > bondRestMax {
		l.rest = bondRestMax
	}
	l.restTill, l.restAt = now.Add(l.rest), now
	l.cap, l.rate = bondLegCapMin, l.rate/2
	for _, c := range b.unacked {
		if c.leg == l {
			l.inflight -= c.n
			c.leg = nil
			if !c.got {
				b.retx = append(b.retx, c)
			}
		}
	}
	sort.Slice(b.retx, func(i, j int) bool { return b.retx[i].off < b.retx[j].off })
	b.cond.Broadcast()
}

// ticker wakes the writers for hedging, sends ACKs nothing else carried, and
// sizes each leg's share from what it delivered.
func (b *Bond) ticker() {
	t := time.NewTicker(bondTick)
	defer t.Stop()
	lastRate := b.now()
	for {
		select {
		case <-b.quit:
			return
		case <-t.C:
		}
		b.mu.Lock()
		if b.rcvNext != b.ackRcv || b.read != b.ackRead || b.ackForce {
			b.ackForce = false
			b.wantAckLocked()
		}
		for l := range b.legs {
			if l.rcvd != l.rcvdAcked {
				l.ackDue = true
			}
		}
		b.stallCheckLocked(b.now())
		if now := b.now(); now.Sub(lastRate) >= bondRateEvery {
			dt := now.Sub(lastRate).Seconds()
			lastRate = now
			for l := range b.legs {
				if l.busy || l.acked > 0 {
					r := float64(l.acked) / dt
					if l.rate == 0 {
						l.rate = r
					} else {
						l.rate = 0.7*l.rate + 0.3*r
					}
					c := int(l.rate * bondLegQueue.Seconds())
					if l.counts && l.minRTT > 0 {
						// Its own delay is known: keep about two round trips
						// on it, and let it grow only while no queue builds
						// (the delay stays near the least seen), so a chunk
						// given to it now is not stuck behind a long line.
						q := 2 * l.minRTT
						if q < l.minRTT+150*time.Millisecond {
							q = l.minRTT + 150*time.Millisecond
						}
						c = int(l.rate * q.Seconds())
						if l.room() <= l.cap/8 && l.delay < l.minRTT*3/2+50*time.Millisecond && c < l.cap*5/4 {
							c = l.cap * 5 / 4
						}
						l.minRTT += l.minRTT / 128 // forget an old least, slowly
					} else if l.inflight >= l.cap && c < l.cap*5/4 {
						// A leg that filled its cap may be held back by it: let
						// it grow, so the cap follows the leg up as well as down.
						c = l.cap * 5 / 4
					}
					if c < bondLegCapMin {
						c = bondLegCapMin
					}
					if c > bondWindow {
						c = bondWindow
					}
					l.cap = c
				}
				l.acked, l.busy = 0, l.inflight > 0 || (l.counts && l.sent > l.peerGot)
			}
		}
		b.cond.Broadcast()
		b.mu.Unlock()
	}
}
