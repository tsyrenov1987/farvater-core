package wire

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// hsgate.go — every TLS handshake the core makes, counted by server name.
//
// A filter that counts ClientHellos to one name from one client sees all of
// them, whoever in the core asked: a flow, a rotation's spare connection, a
// resumed session, the losing side of a race. The brain's governor paces
// only the dials flows make. So the count is kept here, under dialSecure,
// which every TLS and REALITY handshake goes through:
//
//   - each handshake is reported with the time since the previous one to the
//     same name and how it ended (WatchHandshakes), for the field journal;
//   - a wire that rides all its flows on one connection (kilvater) asks for a
//     slot first: at least hsMinGap, plus up to hsGapJitter, after the previous
//     one to the name, and no more than hsPerWindow in hsWindow. A handshake
//     that would wait longer than the short gap is refused (ErrHandshakePaced)
//     rather than held;
//   - for hsFPHold after a handshake to a name failed, a handshake to it with
//     another fingerprint is refused: a name that just dropped one browser's
//     ClientHello does not get a second browser's from the same client.
//
// Wires that handshake once per flow (REALITY, plain TLS) are counted but not
// held: two handshakes a minute would be the end of them.

// ErrHandshakePaced is returned instead of a connection when the handshake
// was not made because of pacing. It says nothing about the path.
var ErrHandshakePaced = errors.New("wire: handshake held back by pacing")

// HandshakeEnd is how a handshake ended.
type HandshakeEnd int

const (
	HandshakeOK      HandshakeEnd = iota
	HandshakeFail                 // refused, reset, or the answer did not verify
	HandshakeTimeout              // no answer in time
)

const (
	hsMinGap    = time.Second
	hsGapJitter = time.Second
	hsWindow    = time.Minute
	hsPerWindow = 2
	hsFPHold    = 10 * time.Minute
)

type hsName struct {
	last   time.Time   // when the last handshake to the name began, any wire's
	slots  []time.Time // the paced handshakes' slots still inside the window
	failAt time.Time   // when a handshake to the name last failed
	failFP string      // and the fingerprint it went out with
}

type hsGate struct {
	mu     sync.Mutex
	names  map[string]*hsName
	now    func() time.Time
	jitter func() time.Duration
}

func newHSGate() *hsGate {
	return &hsGate{
		names:  map[string]*hsName{},
		now:    time.Now,
		jitter: func() time.Duration { return rand.N(hsGapJitter) },
	}
}

var (
	handshakes = newHSGate()
	hsWatch    atomic.Pointer[func(path string, gapMs int64, end HandshakeEnd)]
)

// WatchHandshakes hands every TLS or REALITY handshake the core finishes to
// f: the path it was for, the milliseconds since the previous handshake to
// the same server name (-1 for the first), and how it ended. A handshake
// its caller abandoned is not reported. f must not block.
func WatchHandshakes(f func(path string, gapMs int64, end HandshakeEnd)) {
	if f == nil {
		hsWatch.Store(nil)
		return
	}
	hsWatch.Store(&f)
}

// ForgetHandshakes drops what the pacing remembers. The count a filter keeps
// is per client address; on a new network the client is a new one.
func ForgetHandshakes() { handshakes.forget() }

func fpName(fp string) string {
	if fp = strings.ToLower(fp); fp == "" {
		return "chrome"
	}
	return fp
}

func (g *hsGate) name(n string) *hsName {
	h := g.names[n]
	if h == nil {
		h = &hsName{}
		g.names[n] = h
	}
	return h
}

func (g *hsGate) forget() {
	g.mu.Lock()
	g.names = map[string]*hsName{}
	g.mu.Unlock()
}

// held reports whether a paced handshake to name with fp would be refused
// now, whatever its deadline: the window is full, or the name is held to
// another fingerprint.
func (g *hsGate) held(name, fp string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	h := g.names[name]
	if h == nil {
		return false
	}
	now := g.now()
	if !h.failAt.IsZero() && now.Sub(h.failAt) < hsFPHold && h.failFP != fpName(fp) {
		return true
	}
	n := 0
	for _, t := range h.slots {
		if now.Sub(t) < hsWindow {
			n++
		}
	}
	if n < hsPerWindow {
		return false
	}
	// The slots are in order: the one hsPerWindow back from the end opens
	// the window.
	oldest := h.slots[len(h.slots)-hsPerWindow]
	return oldest.Add(hsWindow).Sub(now) > hsMinGap+hsGapJitter
}

// reserve takes the next slot for a paced handshake to name with fingerprint
// fp and waits for it. The slot must be given back (cancel) if no ClientHello
// goes out after all.
func (g *hsGate) reserve(ctx context.Context, name, fp string) (time.Time, error) {
	g.mu.Lock()
	h, now := g.name(name), g.now()
	if !h.failAt.IsZero() && now.Sub(h.failAt) < hsFPHold && h.failFP != fpName(fp) {
		g.mu.Unlock()
		return time.Time{}, ErrHandshakePaced
	}
	keep := h.slots[:0]
	for _, t := range h.slots {
		if now.Sub(t) < hsWindow {
			keep = append(keep, t)
		}
	}
	h.slots = keep
	slot := now
	if n := len(h.slots); n > 0 {
		if t := h.slots[n-1].Add(hsMinGap + g.jitter()); t.After(slot) {
			slot = t
		}
		if n >= hsPerWindow {
			if t := h.slots[n-hsPerWindow].Add(hsWindow); t.After(slot) {
				slot = t
			}
		}
	}
	wait := slot.Sub(now)
	if dl, ok := ctx.Deadline(); wait > hsMinGap+hsGapJitter || (ok && dl.Before(slot)) {
		g.mu.Unlock()
		return time.Time{}, ErrHandshakePaced
	}
	h.slots = append(h.slots, slot)
	g.mu.Unlock()
	if wait > 0 {
		t := time.NewTimer(wait)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
			g.cancel(name, slot)
			return time.Time{}, ctx.Err()
		}
	}
	return slot, nil
}

func (g *hsGate) cancel(name string, slot time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	h := g.names[name]
	if h == nil {
		return
	}
	for i, t := range h.slots {
		if t.Equal(slot) {
			h.slots = append(h.slots[:i], h.slots[i+1:]...)
			return
		}
	}
}

// begin notes a handshake to name starting now and returns the milliseconds
// since the previous one, or -1.
func (g *hsGate) begin(name string) int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	h, now := g.name(name), g.now()
	gap := int64(-1)
	if !h.last.IsZero() {
		gap = max(0, now.Sub(h.last).Milliseconds())
	}
	h.last = now
	return gap
}

// done notes how the handshake begun with gap ended, and reports it.
func (g *hsGate) done(ctx context.Context, path, name, fp string, gap int64, err error) {
	end := HandshakeOK
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			return // given up on, not failed
		}
		end = HandshakeFail
		var ne net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
			end = HandshakeTimeout
		}
		g.mu.Lock()
		h := g.name(name)
		h.failAt, h.failFP = g.now(), fpName(fp)
		g.mu.Unlock()
	}
	if f := hsWatch.Load(); f != nil {
		(*f)(path, gap, end)
	}
}
