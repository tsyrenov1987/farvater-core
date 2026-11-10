package switchboard

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/tsyrenov1987/farvater-core/brain"
)

// A catalogue changes under a running tunnel (a node moves to another
// address): the apps build a second switchboard over the new catalogue and
// hand it the first one's listening socket. The port and the credentials stay,
// so the tunnel never notices; flows already open finish on the old
// switchboard, every new one goes to the new.

// Handover states of the accept loop.
const (
	serving  = 0
	letGo    = 1 // Detach asked the loop to let the listener go
	detached = 2 // the loop let go and returned
)

type deadliner interface{ SetDeadline(time.Time) error }

// Detach takes the listening socket away from the accept loop without closing
// it, waiting up to wait for the loop to let go, and retires the switchboard:
// it no longer writes the memory file, which the next one owns. Its open flows
// run on until its context ends. On an error the loop keeps serving.
func (s *Switchboard) Detach(wait time.Duration) (net.Listener, error) {
	s.lnMu.Lock()
	ln := s.ln
	s.lnMu.Unlock()
	if ln == nil {
		return nil, errors.New("switchboard: not listening")
	}
	d, ok := ln.(deadliner)
	if !ok {
		return nil, errors.New("switchboard: this listener cannot be handed over")
	}
	if !s.handing.CompareAndSwap(serving, letGo) {
		return nil, errors.New("switchboard: already handed over")
	}
	_ = d.SetDeadline(time.Now()) // wakes the Accept that waits
	select {
	case <-s.letGone:
	case <-time.After(wait):
		if s.handing.CompareAndSwap(letGo, serving) {
			_ = d.SetDeadline(time.Time{})
			return nil, errors.New("switchboard: the accept loop did not let go")
		}
		<-s.letGone
	}
	s.lnMu.Lock()
	ln = s.ln
	s.ln = nil
	s.lnMu.Unlock()
	if d, ok := ln.(deadliner); ok {
		_ = d.SetDeadline(time.Time{})
	}
	s.mu.Lock()
	s.retired = true
	s.mu.Unlock()
	return ln, nil
}

// StartOn serves on a listener another switchboard let go (Detach) until ctx
// ends.
func (s *Switchboard) StartOn(ctx context.Context, ln net.Listener) {
	go func() { _ = s.serveListener(ctx, ln) }()
}

// Inherit carries what the session has counted so far over from the
// switchboard this one replaces, so the apps' counters go on where they were:
// uptime, flows, receipts, and the bytes of each path both catalogues have
// (shared counters: flows still open on old keep adding to them). Call it
// before StartOn.
func (s *Switchboard) Inherit(old *Switchboard) {
	old.mu.Lock()
	receipts := append([]brain.Receipt(nil), old.receipts...)
	served, blocked, slept := old.served, old.blocked, old.slept
	want := map[string]int64{}
	for id, t := range old.wantTill {
		want[id] = t
	}
	old.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started = old.started
	s.flows.Store(old.flows.Load())
	s.retries.Store(old.retries.Load())
	s.udp.Store(old.udp.Load())
	s.direct.Store(old.direct.Load())
	s.receipts = receipts
	s.served, s.blocked, s.slept = served, blocked, slept
	for id := range s.carried {
		if c, ok := old.carried[id]; ok {
			s.carried[id] = c
		}
	}
	for id, t := range want {
		if _, ok := s.wires[id]; ok {
			s.wantTill[id] = t
		}
	}
}

// Active is the number of SOCKS connections open now.
func (s *Switchboard) Active() int64 { return s.active.Load() }

// Ctx is the network the brain files evidence under now.
func (s *Switchboard) Ctx() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Ctx()
}

// Restricted reports whether the brain is in the restricted variant of its
// network (allow-listed sites answer, the paths do not).
func (s *Switchboard) Restricted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Restricted()
}

// EnterRestricted puts a new switchboard's brain in the restricted variant of
// its network straight away, where the switchboard it replaces stood (a
// catalogue reload on a restricted network): the allow-listed paths stay
// first, and the plain paths answering again end it as usual. Call it before
// StartOn.
func (s *Switchboard) EnterRestricted() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.EnterRestricted(nowMs())
}

// Discard closes the wires of a switchboard that never served (a reload that
// lost its race with Stop).
func (s *Switchboard) Discard() {
	for _, w := range s.wires {
		w.Close()
	}
}
