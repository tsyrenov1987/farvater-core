package kilvater

import (
	"encoding/binary"
	"errors"
	"io"
	"sort"
	"strings"
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

// JoinSpare in a JOIN's flags marks a leg whose route is to be spared (a
// narrow shared port, as the CDN relay's): each end gives it new chunks only
// while no other leg has room for them, so a flow the other legs can carry
// alone leaves it nearly idle, and a flow that fills them still gets the sum.
// It still carries copies of a held-up head and what a dead leg dropped. An
// end that does not know the flag treats the leg as any other.
const JoinSpare byte = 2

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
	bondWriteHeld  = 10 * time.Millisecond // a write longer than this is one the route holds back
	bondLateShare  = 0.75                  // of the window the others may fill before a leg's chunk arrives
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
	spare    bool      // see JoinSpare
	writing  time.Time // since when its writer has been in a write; zero when it is not
	rate     float64   // bytes per second, smoothed
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

	// what it did, for LegStats
	name   string
	since  time.Time
	rests  int    // times it was rested as stalled
	hedges int    // copies of a held-up head it carried
	retx   int    // chunks it carried again after another leg lost them
	end    string // why it ended (the first cause)
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

	// counts, for Stats
	gone      map[string]*LegStats // the legs that ended, by name
	dupBytes  uint64               // payload that arrived a second time
	oooMax    int                  // the most that ever waited out of order
	holes     int                  // times the order was held up by a missing chunk
	holeSince time.Time            // when the present hole opened; zero when none
	holeWait  time.Duration        // all the time spent waiting on holes
	holeMax   time.Duration

	// OnLegEnd, if set before the first leg runs, is called with each leg's
	// counts as it ends.
	OnLegEnd func(LegStats)
}

// LegStats is what the legs of one name did in a bond: one leg, or the same
// route joined again and again.
type LegStats struct {
	Name   string
	Joins  int            // legs run under this name
	Live   int            // of them, carrying now
	Sent   uint64         // SEQ payload given to it, copies included
	Rcvd   uint64         // SEQ payload read off it, copies included
	Rests  int            // times it was rested as stalled
	Hedges int            // copies of a held-up head it carried
	Retx   int            // chunks it carried again after another leg lost them
	RTT    time.Duration  // smoothed time from a chunk going out to the far end having it (the last leg's)
	MinRTT time.Duration  // the least seen
	Rate   float64        // bytes a second it delivered lately
	Dur    time.Duration  // how long its legs ran, added up
	Ends   map[string]int // why its legs ended
}

// BondStats is one end's view of a bond.
type BondStats struct {
	Legs     []LegStats
	DupBytes uint64        // payload received twice (hedges, repeats)
	OOOMax   int           // the most payload that waited out of order
	Holes    int           // times the order was held up by a missing chunk
	HoleWait time.Duration // the time spent so
	HoleMax  time.Duration // the longest such wait
}

func (l *bondLeg) stats(now time.Time, live bool) LegStats {
	st := LegStats{Name: l.name, Joins: 1, Sent: l.sent, Rcvd: l.rcvd, Rests: l.rests, Hedges: l.hedges,
		Retx: l.retx, RTT: l.delay, MinRTT: l.minRTT, Rate: l.rate, Dur: now.Sub(l.since)}
	if live {
		st.Live = 1
	} else {
		end := l.end
		if end == "" {
			end = "unknown"
		}
		st.Ends = map[string]int{end: 1}
	}
	return st
}

func (a *LegStats) add(o LegStats) {
	a.Joins += o.Joins
	a.Live += o.Live
	a.Sent += o.Sent
	a.Rcvd += o.Rcvd
	a.Rests += o.Rests
	a.Hedges += o.Hedges
	a.Retx += o.Retx
	a.Dur += o.Dur
	if o.RTT > 0 {
		a.RTT, a.Rate = o.RTT, o.Rate
	}
	if o.MinRTT > 0 && (a.MinRTT == 0 || o.MinRTT < a.MinRTT) {
		a.MinRTT = o.MinRTT
	}
	for k, v := range o.Ends {
		if a.Ends == nil {
			a.Ends = map[string]int{}
		}
		a.Ends[k] += v
	}
}

// Stats reports what the bond and its legs did so far, legs in name order.
func (b *Bond) Stats() BondStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	by := map[string]*LegStats{}
	for n, g := range b.gone {
		c := *g
		c.Ends = map[string]int{}
		for k, v := range g.Ends {
			c.Ends[k] = v
		}
		by[n] = &c
	}
	for l := range b.legs {
		if a := by[l.name]; a != nil {
			a.add(l.stats(now, true))
		} else {
			st := l.stats(now, true)
			by[l.name] = &st
		}
	}
	out := BondStats{DupBytes: b.dupBytes, OOOMax: b.oooMax, Holes: b.holes, HoleWait: b.holeWait, HoleMax: b.holeMax}
	if !b.holeSince.IsZero() {
		d := now.Sub(b.holeSince)
		out.HoleWait += d
		if d > out.HoleMax {
			out.HoleMax = d
		}
	}
	for _, a := range by {
		out.Legs = append(out.Legs, *a)
	}
	sort.Slice(out.Legs, func(i, j int) bool { return out.Legs[i].Name < out.Legs[j].Name })
	return out
}

// endLocked notes why a leg ended; the first cause stands.
func (l *bondLeg) endLocked(why string) {
	if l.end == "" {
		l.end = why
	}
}

// ErrClass names an error in a word, for counts by cause.
func ErrClass(err error) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "eof"
	}
	var te interface{ Timeout() bool }
	if errors.As(err, &te) && te.Timeout() {
		return "timeout"
	}
	m := strings.ToLower(err.Error())
	for _, w := range [][2]string{
		{"quota", "quota"}, {"486", "quota"}, {"unauthorized", "auth"}, {"401", "auth"}, {"stale", "auth"},
		{"no relay allocation", "alloc"}, {"all retransmissions", "noanswer"},
		{"deadline", "timeout"}, {"timeout", "timeout"}, {"timed out", "timeout"},
		{"canceled", "canceled"}, {"goaway", "goaway"}, {"rst_stream", "rst"}, {"stream error", "rst"},
		{"reset", "reset"}, {"refused", "refused"}, {"broken pipe", "pipe"}, {"closed", "closed"},
		{"unreachable", "unreach"}, {"no route", "unreach"}, {"tls", "tls"}, {"certificate", "tls"},
		{"status", "status"}, {"eof", "eof"},
	} {
		if strings.Contains(m, w[0]) {
			return w[1]
		}
	}
	return "other"
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
	return b.RunLegNamed(rw, accept, "")
}

// RunLegNamed is RunLeg for a leg that Stats reports under name (its route).
func (b *Bond) RunLegNamed(rw io.ReadWriteCloser, accept bool, name string) bool {
	return b.RunLegSpare(rw, accept, name, false)
}

// RunLegSpare is RunLegNamed for a leg that may be one to spare (JoinSpare).
func (b *Bond) RunLegSpare(rw io.ReadWriteCloser, accept bool, name string, spare bool) bool {
	l := &bondLeg{rw: rw, cap: bondLegCapInit, ackDue: accept, done: make(chan struct{}), name: name, spare: spare}
	b.mu.Lock()
	l.since = b.now()
	if b.closed {
		cb := b.OnLegEnd
		b.mu.Unlock()
		rw.Close()
		if cb != nil {
			l.end = "done"
			cb(l.stats(l.since, false))
		}
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
	st := l.stats(b.now(), false)
	if !l.accepted {
		st.Ends = map[string]int{"refused:" + l.end: 1} // the far end never answered on it
	}
	if b.gone == nil {
		b.gone = map[string]*LegStats{}
	}
	if a := b.gone[l.name]; a != nil {
		a.add(st)
	} else {
		c := st
		b.gone[l.name] = &c
	}
	cb, ok := b.OnLegEnd, l.accepted
	b.mu.Unlock()
	if cb != nil {
		cb(st)
	}
	return ok
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
	why := "proto"
	defer func() {
		b.mu.Lock()
		if b.closed {
			why = "done"
		}
		l.endLocked(why)
		b.legDeadLocked(l)
		b.mu.Unlock()
		l.rw.Close()
	}()
	var buf []byte
	for {
		typ, body, err := ReadFrame(l.rw, buf)
		if err != nil {
			why = "read:" + ErrClass(err)
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
			b.mu.Lock()
			l.endLocked("close" + string(rune('0'+code%10)))
			b.mu.Unlock()
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
		b.dupBytes += uint64(len(data))
		return // a copy of what we have
	}
	if end < off || off < b.rcvNext || end > b.read+uint64(bondWindow)+uint64(bondChunk) {
		return // not on a chunk boundary we know, or past the window: drop
	}
	if _, dup := b.ooo[off]; dup {
		b.dupBytes += uint64(len(data))
		return
	}
	// An honest sender cuts the flow into chunks that do not overlap, so what
	// waits out of order never passes the window. Chunks at offsets one byte
	// apart would each be kept whole (KL-01): drop what would pass it, the
	// sender sends it again.
	if b.oooBytes+len(data) > bondWindow+bondChunk {
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
	if b.oooBytes > b.oooMax {
		b.oooMax = b.oooBytes
	}
	if b.oooBytes > 0 && b.holeSince.IsZero() {
		b.holeSince = b.now()
		b.holes++
	} else if b.oooBytes == 0 && !b.holeSince.IsZero() {
		d := b.now().Sub(b.holeSince)
		b.holeSince = time.Time{}
		b.holeWait += d
		if d > b.holeMax {
			b.holeMax = d
		}
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

// lateLocked reports whether a new chunk given to l now would arrive only
// after the other legs have filled most of the window behind it: the flow
// would then wait on it, at this leg's pace. Such a leg takes one chunk at a
// time (which keeps its rate and delay measured) until it is quicker.
func (b *Bond) lateLocked(l *bondLeg, now time.Time) bool {
	out := l.inflight
	if l.counts {
		out = int(l.sent - l.peerGot)
	}
	if out <= 0 || l.rate <= 0 {
		return false
	}
	others := 0.0
	for o := range b.legs {
		if o != l && !o.dead && !now.Before(o.restTill) {
			others += o.rate
		}
	}
	if others <= 0 {
		return false
	}
	way := l.minRTT
	if way == 0 {
		way = l.delay
	}
	eta := float64(out)/l.rate + way.Seconds()/2
	return eta > bondLateShare*float64(bondWindow)/others
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
				l.hedges++
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
		l.retx++
		l.mark(c, now)
		return c
	}
	if len(b.unacked) > 0 && len(b.legs) > 1 {
		h := b.unacked[0]
		if h.leg != l && !h.got && now.Sub(b.progress) >= bondHedgeAfter && now.Sub(h.hedgedAt) >= bondHedgeAfter {
			h.hedgedAt = now
			l.hedges++
			l.mark(h, now)
			return h
		}
	}
	if len(b.pending) > 0 {
		if l.spare && b.otherHasRoomLocked(l, now) {
			return nil // the leg with room takes it
		}
		if b.lateLocked(l, now) {
			return nil // it would come after the others have filled the window
		}
		c := b.pending[0]
		b.pending[0] = nil
		b.pending = b.pending[1:]
		c.leg, c.sentAt = l, now
		l.inflight += c.n
		l.mark(c, now)
		b.unacked = append(b.unacked, c)
		if !l.spare && l.room() <= 0 && len(b.pending) > 0 {
			b.cond.Broadcast() // it is full: a spared leg may take the rest
		}
		return c
	}
	return nil
}

// otherHasRoomLocked reports whether a leg that is not to be spared can take
// a new chunk now.
func (b *Bond) otherHasRoomLocked(l *bondLeg, now time.Time) bool {
	for o := range b.legs {
		if o == l || o.spare || o.dead || now.Before(o.restTill) || o.room() <= 0 {
			continue
		}
		// A leg whose write does not return is held back by its route (the
		// socket is full): it has room by its cap, and cannot take a chunk.
		if o.writing.IsZero() || now.Sub(o.writing) < bondWriteHeld {
			return true
		}
	}
	return false
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
				l.endLocked("done")
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
		l.writing = b.now()
		b.mu.Unlock()
		err := WriteFrame(l.rw, typ, body)
		b.mu.Lock()
		l.writing = time.Time{}
		b.mu.Unlock()
		if err != nil {
			b.mu.Lock()
			l.endLocked("write:" + ErrClass(err))
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
	l.rests++
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
