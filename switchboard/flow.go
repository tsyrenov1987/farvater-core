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
	pin          string // the only path that may carry the flow (a sweep's probe)

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
	start   time.Time // carries the monotonic reading sleptMs needs
	startMs int64
	readyMs int64 // 0 = never
	dialAt  int64 // when the dial began, its pacing waited out; 0 = never
	m       *meter
	// condemned: closed while stuck on a path the breaker condemned
	condemned bool
}

func (f *flow) newAttempt(path string, explore bool) *attempt {
	start := time.Now()
	return &attempt{path: path, explore: explore, start: start, startMs: start.UnixMilli(), m: &meter{f: f, c: f.s.carried[path]}}
}

func (a *attempt) base(f *flow, now int64) brain.Receipt {
	r := brain.Receipt{
		Path: a.path, AtMs: now,
		WireReadyMs: -1, FirstByteMs: -1, DownAtFail: -1,
		Dst: f.target.Host, DstClass: f.class, Explore: a.explore,
		DurMs: now - a.startMs, SleptMs: sleptMs(a.start),
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
	r.BusyMs, r.BusyDown, r.GoodputNoted = s.busyMs, s.busyDown, s.noted
	r.Stalls, r.StallNoted = s.stalls, s.stallNoted
	if s.firstDownAt > 0 {
		r.FirstByteMs = s.firstDownAt - a.startMs
		if preludeLen > 0 && a.dialAt > 0 {
			r.AnswerMs = max(1, s.firstDownAt-a.dialAt)
		}
	}
	// The app closed while still waiting for an answer to what it sent: the
	// path took it and let nothing back, a stall it gave up on.
	unanswered := s.asked >= brain.UnansweredBytes && now-s.askedAt >= brain.UnansweredMs
	switch out {
	case wire.OutcomeRemoteFin:
		r.End = brain.EndRemoteFin
	case wire.OutcomeClientFin:
		r.End = brain.EndLocalClose
		if s.inStall || unanswered {
			r.End = brain.EndStallAbandon
		}
	case wire.OutcomeCanceled:
		r.End = brain.EndLocalClose
		if fbTimeout {
			r.End = brain.EndTimeout
		} else if unanswered || a.condemned {
			r.End = brain.EndStallAbandon
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

	var dec brain.Decision
	if f.pin != "" {
		s.mu.Lock()
		dec = s.b.Pinned(f.pin)
		s.mu.Unlock()
	} else {
		dec = s.pick(nowMs(), f.target.Host, f.class)
	}
	if dec.Primary == "" {
		return // every path is asleep: nothing to carry the flow
	}
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
		if fbTimeout {
			// Ready yet unanswered: a connection the path shares across flows
			// may have died in silence, so the next flow dials a fresh one.
			s.refresh(a.path, a.start)
		}
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
	if err := f.s.pace(ctx, a.path); err != nil {
		return nil, err
	}
	a.dialAt = nowMs()
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
	var first *attempt
	firstDone := false
	launch := func(id string, ex bool) {
		a := f.newAttempt(id, ex)
		if first == nil {
			first = a
		}
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
			if r.a == first {
				firstDone = true
			}
			if r.err == nil {
				// First ready wins; drain the losing dials in the background.
				cancelAll()
				go f.drain(results, launched-finished)
				// The first dial lost the race if it still hung (one that
				// failed on its own filed its receipt).
				if r.a == first || !firstDone {
					f.s.noteRace(first.path, r.a != first, first.startMs)
				}
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
	if a.m.c != nil {
		// The first payload rides with the proxy request, past the meter: the
		// path carries it all the same.
		a.m.c.up.Add(int64(len(prelude)))
	}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type res struct {
		out wire.Outcome
		err error
	}
	if fr, ok := sess.(wire.Framed); ok {
		a.m.held = fr.InRecord
	}
	done := make(chan res, 1)
	go func() {
		o, e := sess.Run(rctx, f.target, prelude, f.up, f.client, a.m)
		done <- res{o, e}
	}()
	// The first-byte deadline wants a fine clock; once the answer has come,
	// stalls (StallMs) are judged as well on a coarse one, and a long idle
	// flow (a messenger's) then wakes the phone once a second, not four times.
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	coarse := false
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
	var wokeAt, slept int64 // when the flow last saw that the device had slept, and for how long in all
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
			if !coarse {
				coarse = true
				tick.Reset(time.Second)
				if sleptMs(a.start) < brain.SleepGraceMs {
					f.s.noteAnswered(a.path, a.startMs) // the path gets through now
				}
			}
			// A connection open while the device slept has likely lost its NAT
			// entry, and the app's request on it waits in silence until the
			// app's own timeout, half a minute or more. Once the app has asked
			// and then waited as long as a new flow waits for its first byte,
			// sending nothing more, the flow is closed and the app reconnects.
			// Its receipt is dropped as slept; the path's shared connection is
			// refreshed as after a first-byte timeout.
			if sl := sleptMs(a.start); sl >= slept+brain.SleepGraceMs {
				wokeAt, slept = now, sl
			}
			if wokeAt > 0 && sn.asked > 0 && now-max(sn.lastUpAt, wokeAt) >= fbMs {
				f.s.lostAt.Store(a.path, now)
				fbTimeout = true
				cancel()
				continue
			}
			// That one flow proves the network forgot the path's connections
			// while the phone slept: the others that slept as well and have
			// heard nothing since waking are closed now, so the app reconnects
			// them before it asks, not after a first-byte deadline on each.
			if lost, ok := f.s.lostAt.Load(a.path); ok && wokeAt > 0 && lost.(int64) >= wokeAt && sn.lastDownAt < wokeAt {
				cancel()
				continue
			}
			a.m.tick(now, f.s.cfg.StallMs)
			// a phone that slept stalls every flow it had open: not the path
			if sleptMs(a.start) < brain.SleepGraceMs && (a.m.stallOnce() || a.m.unansweredOnce(now, f.s.cfg.StallMs)) {
				f.s.noteStall(a.path, a.startMs)
			}
			// A path the breaker condemned (frozen, shaped, cut) keeps the flows
			// already on it open in silence until the app's own timeout. One
			// that stalled, or asked and got nothing back for as long as a new
			// flow waits for its first byte, is closed: the app reconnects at
			// once and its new flow goes to another path.
			if sn = a.m.snap(); (sn.inStall || sn.asked > 0 && now-sn.askedAt >= fbMs) && f.s.tripped(a.path, now) {
				a.condemned = true
				cancel()
				continue
			}
			if a.m.noteOnce() {
				sn = a.m.snap()
				f.s.noteGoodput(a.path, sn.busyDown, sn.busyMs, a.startMs)
			}
			// a sweep's probe reports itself (Swept)
			if f.pin == "" && sleptMs(a.start) < brain.SleepGraceMs && a.m.slowOnce() {
				sn = a.m.snap()
				f.s.noteSlow(a.path, sn.heldDown, sn.heldMs, a.startMs)
			}
		}
	}
}
