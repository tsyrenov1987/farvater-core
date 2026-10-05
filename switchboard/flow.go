package switchboard

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/tsyrenov1987/farvater-core/brain"
	"github.com/tsyrenov1987/farvater-core/wire"
)

// flow is one app connection from SOCKS accept to close.
type flow struct {
	s            *Switchboard
	client       net.Conn
	target       wire.Target
	class        brain.DstClass
	up           chan []byte
	done         chan struct{}
	fbDeadlineMs int64

	pmu      sync.Mutex
	prelude  []byte
	overflow bool
}

func (f *flow) recordPrelude(p []byte) {
	f.pmu.Lock()
	defer f.pmu.Unlock()
	if f.overflow {
		return
	}
	if len(f.prelude)+len(p) > f.s.cfg.PreludeCap {
		f.overflow = true
		return
	}
	f.prelude = append(f.prelude, p...)
}

func (f *flow) preludeCopy() ([]byte, bool) {
	f.pmu.Lock()
	defer f.pmu.Unlock()
	return append([]byte(nil), f.prelude...), !f.overflow
}

// readLoop moves app bytes into the up channel until the app closes.
func (f *flow) readLoop() {
	defer close(f.up)
	buf := make([]byte, 16*1024)
	for {
		n, err := f.client.Read(buf)
		if n > 0 {
			p := make([]byte, n)
			copy(p, buf[:n])
			select {
			case f.up <- p:
			case <-f.done:
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// attempt is one try of one path for a flow.
type attempt struct {
	path    string
	explore bool
	startMs int64
	readyMs int64 // 0 = never
	m       *meter
}

func (f *flow) newAttempt(path string, explore bool) *attempt {
	return &attempt{path: path, explore: explore, startMs: nowMs(), m: &meter{f: f}}
}

func (a *attempt) base(f *flow, now int64) brain.Receipt {
	r := brain.Receipt{
		Path: a.path, Ctx: f.s.cfg.Ctx, AtMs: now,
		WireReadyMs: -1, FirstByteMs: -1, DownAtFail: -1,
		Dst: f.target.Host, DstClass: f.class, Explore: a.explore,
		DurMs: now - a.startMs,
	}
	if a.readyMs > 0 {
		r.WireReadyMs = a.readyMs - a.startMs
	}
	return r
}

// dialFail is the receipt of a dial that never produced a session.
func (a *attempt) dialFail(f *flow, err error) brain.Receipt {
	r := a.base(f, nowMs())
	r.End = brain.EndWireReset
	if errors.Is(err, context.DeadlineExceeded) {
		r.End = brain.EndTimeout
	}
	return r
}

// runReceipt is the receipt of an attempt that ran a session.
func (a *attempt) runReceipt(f *flow, preludeLen int, out wire.Outcome, err error, fbTimeout bool) brain.Receipt {
	now := nowMs()
	r := a.base(f, now)
	s := a.m.snap()
	r.Up = s.up + int64(preludeLen)
	r.Down = s.down
	r.MaxGapMs = s.maxGap
	r.Stalls = s.stalls
	if s.firstDownAt > 0 {
		r.FirstByteMs = s.firstDownAt - a.startMs
	}
	switch out {
	case wire.OutcomeRemoteFin:
		r.End = brain.EndRemoteFin
	case wire.OutcomeClientFin:
		r.End = brain.EndLocalClose
		if s.inStall {
			r.End = brain.EndStallAbandon
		}
	case wire.OutcomeCanceled:
		r.End = brain.EndLocalClose
		if fbTimeout {
			r.End = brain.EndTimeout
		}
	default:
		r.End = brain.EndWireReset
		if errors.Is(err, wire.ErrWireDead) {
			r.WireReadyMs = -1
		}
	}
	switch r.End {
	case brain.EndWireReset, brain.EndTimeout, brain.EndStallAbandon:
		r.DownAtFail = r.Down
	}
	return r
}

// serve runs the whole flow. The SOCKS handshake is already done and the
// first payload (if any) is in f.prelude.
func (f *flow) serve(ctx context.Context) {
	defer close(f.done)
	defer f.client.Close()
	s := f.s

	dec := s.pick(nowMs(), f.target.Host, f.class)
	f.fbDeadlineMs = dec.FirstByteDeadlineMs
	order := []string{dec.Primary}
	if dec.Secondary != "" && dec.Secondary != dec.Primary {
		order = append(order, dec.Secondary)
	}
	if dec.Tertiary != "" && dec.Tertiary != dec.Primary && dec.Tertiary != dec.Secondary {
		order = append(order, dec.Tertiary) // storm mode: a third, diverse dial
	}

	sess, a, err := f.dialRace(ctx, order, dec.StaggerMs, dec.Explore)
	if err != nil {
		return
	}
	tried := map[string]bool{a.path: true}
	for {
		prelude, retryable := f.preludeCopy()
		out, rerr, fbTimeout, sawBytes := f.run(ctx, sess, a, prelude)
		r := a.runReceipt(f, len(prelude), out, rerr, fbTimeout)
		s.observe(r)
		if sawBytes || out == wire.OutcomeRemoteFin || out == wire.OutcomeClientFin || ctx.Err() != nil {
			return
		}
		// Failed before the first byte: the app has not seen anything yet, so
		// another path can take over transparently.
		prelude, retryable = f.preludeCopy()
		next := ""
		for _, id := range order {
			if !tried[id] {
				next = id
				break
			}
		}
		if !retryable || next == "" {
			return
		}
		tried[next] = true
		s.retries.Add(1)
		a = f.newAttempt(next, false)
		sess, err = f.dialOne(ctx, a)
		if err != nil {
			s.observe(a.dialFail(f, err))
			return
		}
	}
}

// dialOne paces and dials a single path.
func (f *flow) dialOne(ctx context.Context, a *attempt) (wire.Session, error) {
	w := f.s.wires[a.path]
	if w == nil {
		return nil, errors.New("no wire")
	}
	if w.NeedsHandshake() {
		slot := f.s.acquire(a.path)
		if wait := slot - nowMs(); wait > 0 {
			select {
			case <-time.After(time.Duration(wait) * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	dctx, cancel := context.WithTimeout(ctx, f.s.cfg.DialTimeout)
	defer cancel()
	sess, err := w.Dial(dctx)
	if err != nil {
		return nil, err
	}
	a.readyMs = nowMs()
	return sess, nil
}

type dialResult struct {
	a    *attempt
	sess wire.Session
	err  error
}

// dialRace dials order[0]; if it is not ready within staggerMs, order[1] is
// dialed too and the first ready session wins. Losers are closed; a loser
// that failed on its own still yields a receipt (a canceled one does not).
func (f *flow) dialRace(ctx context.Context, order []string, staggerMs int64, explore bool) (wire.Session, *attempt, error) {
	results := make(chan dialResult, len(order))
	rctx, cancelAll := context.WithCancel(ctx)
	defer cancelAll()
	launch := func(id string, ex bool) {
		a := f.newAttempt(id, ex)
		go func() {
			sess, err := f.dialOne(rctx, a)
			results <- dialResult{a, sess, err}
		}()
	}
	launch(order[0], explore)
	launched, finished := 1, 0
	nextStagger := func() <-chan time.Time {
		if launched < len(order) {
			return time.After(time.Duration(staggerMs) * time.Millisecond)
		}
		return nil
	}
	timer := nextStagger()
	for finished < launched {
		select {
		case <-timer:
			// The current dials are slow but not yet failed: add the next one.
			if launched < len(order) {
				launch(order[launched], false)
				launched++
			}
			timer = nextStagger()
		case r := <-results:
			finished++
			if r.err == nil {
				// First ready wins; drain the losing dials in the background.
				cancelAll()
				go f.drain(results, launched-finished)
				return r.sess, r.a, nil
			}
			if rctx.Err() == nil {
				f.s.observe(r.a.dialFail(f, r.err))
			}
			if launched < len(order) {
				// A dial failed: bring the next one up immediately (Happy
				// Eyeballs across rails), do not wait out the stagger.
				launch(order[launched], false)
				launched++
				timer = nextStagger()
			}
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
	return nil, nil, errors.New("no path connected")
}

func (f *flow) drain(results chan dialResult, n int) {
	for i := 0; i < n; i++ {
		r := <-results
		if r.err == nil {
			r.sess.Close()
		}
	}
}

// run executes one session with the first-byte watchdog and stall accounting.
func (f *flow) run(ctx context.Context, sess wire.Session, a *attempt, prelude []byte) (out wire.Outcome, err error, fbTimeout bool, sawBytes bool) {
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type res struct {
		out wire.Outcome
		err error
	}
	done := make(chan res, 1)
	go func() {
		o, e := sess.Run(rctx, f.target, prelude, f.up, f.client, a.m)
		done <- res{o, e}
	}()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	fbMs := f.fbDeadlineMs
	if fbMs <= 0 {
		fbMs = f.s.cfg.FirstByteTimeout.Milliseconds()
	}
	// The first-byte clock runs from the app's first bytes: a connection the
	// app has not used yet is waiting for nothing.
	var askedAt int64
	if len(prelude) > 0 {
		askedAt = nowMs()
	}
	for {
		select {
		case r := <-done:
			sn := a.m.snap()
			return r.out, r.err, fbTimeout, sn.firstDownAt > 0
		case <-tick.C:
			now := nowMs()
			sn := a.m.snap()
			if sn.firstDownAt == 0 {
				if askedAt == 0 {
					askedAt = sn.firstUpAt
				}
				if askedAt > 0 && now > askedAt+fbMs && !fbTimeout {
					fbTimeout = true
					cancel()
				}
				continue
			}
			a.m.tick(now, f.s.cfg.StallMs)
		}
	}
}
