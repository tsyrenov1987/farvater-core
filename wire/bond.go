package wire

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tsyrenov1987/farvater-core/kilvater"
)

// A kilbond:// link is one path made of several kilvater links to the same
// server, each by its own route (a CDN relay, VK's call relays, ...). Every
// TCP flow on it is cut into chunks spread over all the legs at once and put
// back in order at the server (kilvater/bond.go), so the flow gets the sum of
// the routes, and survives one of them dropping:
//
//	kilbond://<anything>?leg=<base64url kilvater:// or vkturn:// link>&leg=...#name
//
// UDP takes the first leg alone. A server without bonds refuses the legs and
// the path fails as a whole, which the brain sees like any dead path.

// KindBond is a bonded kilvater path (Legs holds its legs).
const KindBond Kind = "kilbond"

func parseBond(raw string) (PathSpec, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return PathSpec{}, err
	}
	spec := PathSpec{Kind: KindBond}
	for _, l := range u.Query()["leg"] {
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(l, "="))
		if err != nil {
			return PathSpec{}, errors.New("kilbond: leg is not base64url")
		}
		ls, err := ParseURI(string(b))
		if err != nil {
			return PathSpec{}, fmt.Errorf("kilbond: leg: %w", err)
		}
		if ls.Kind != KindKilvater {
			return PathSpec{}, errors.New("kilbond: legs must be kilvater")
		}
		spec.Legs = append(spec.Legs, ls)
	}
	if len(spec.Legs) < 2 || len(spec.Legs) > 4 {
		return PathSpec{}, errors.New("kilbond: needs 2 to 4 legs")
	}
	first := spec.Legs[0]
	spec.Host, spec.Port, spec.SNI = first.Host, first.Port, first.SNI
	if f, err := url.PathUnescape(u.Fragment); err == nil && f != "" {
		spec.ID = f
	} else {
		spec.ID = "kilbond"
	}
	return spec, nil
}

type bondWire struct {
	spec  PathSpec
	legs  []*kilWire
	tune  *bondTune // tests; nil = the package defaults
	stats []legCount

	// A leg that never got into a flow rests before the next flows try it (see
	// bondLegRest): unix ms until when, and how long the rest was.
	restTill, restFor []atomic.Int64

	// what the flows waited on chunks out of order, downstream (see kilvater.BondStats)
	holes, holeMs, holeMax, oooMax, dup atomic.Int64
}

// legCount is what one leg did over all the bond's flows this session.
type legCount struct {
	down, up            atomic.Int64 // bytes read and written on the leg's streams, frames included
	drops, backs, fails atomic.Int64 // dropped while carrying, back into a flow after a drop, opens that failed

	rests, hedges, retx atomic.Int64 // from the bond: rested as stalled, carried a copy of a held-up chunk, a lost one again
	rtt, minRTT, durMs  atomic.Int64 // ms: the last leg's smoothed chunk delay, the least seen, time the legs ran

	mu  sync.Mutex
	why map[string]int64 // why legs failed to open or ended, by cause
}

// maxLegWhy caps the causes kept apart for one leg.
const maxLegWhy = 12

func (c *legCount) cause(k string, n int64) {
	c.mu.Lock()
	if c.why == nil {
		c.why = map[string]int64{}
	}
	if _, ok := c.why[k]; !ok && len(c.why) >= maxLegWhy {
		k = "other"
	}
	c.why[k] += n
	c.mu.Unlock()
}

// ended takes in what one leg did in a flow (kilvater.LegStats).
func (c *legCount) ended(st kilvater.LegStats) {
	c.rests.Add(int64(st.Rests))
	c.hedges.Add(int64(st.Hedges))
	c.retx.Add(int64(st.Retx))
	c.durMs.Add(st.Dur.Milliseconds())
	if st.RTT > 0 {
		c.rtt.Store(st.RTT.Milliseconds())
	}
	if m := st.MinRTT.Milliseconds(); m > 0 && (c.minRTT.Load() == 0 || m < c.minRTT.Load()) {
		c.minRTT.Store(m)
	}
	for k, n := range st.Ends {
		if k != "done" { // the flow ended: not the leg's doing
			c.cause(k, int64(n))
		}
	}
}

// BondLegStat is one leg of a bond for the status (and Orden's journal):
// how much it carried and how often it dropped out and came back.
type BondLegStat struct {
	Leg   string `json:"leg"`
	Down  int64  `json:"d"`
	Up    int64  `json:"u"`
	Drops int64  `json:"drop,omitempty"`
	Backs int64  `json:"back,omitempty"`
	Fails int64  `json:"fail,omitempty"`

	Rests  int64            `json:"st,omitempty"`   // times the bond rested it as stalled
	Hedges int64            `json:"hg,omitempty"`   // copies of a held-up chunk it carried
	Retx   int64            `json:"rx,omitempty"`   // chunks it carried again after another leg lost them
	RTT    int64            `json:"rtt,omitempty"`  // ms, smoothed: a chunk out to the far end having it
	MinRTT int64            `json:"mrtt,omitempty"` // ms, the least seen
	Ms     int64            `json:"ms,omitempty"`   // how long its legs ran
	Why    map[string]int64 `json:"why,omitempty"`  // causes of its fails and drops

	// On the entry named "*" only, for the bond as a whole (downstream):
	Holes   int64 `json:"ho,omitempty"`  // times the order waited for a missing chunk
	HoleMs  int64 `json:"hw,omitempty"`  // ms spent waiting so
	HoleMax int64 `json:"hm,omitempty"`  // the longest wait, ms
	OOOMax  int64 `json:"ooo,omitempty"` // the most bytes held out of order
	Dup     int64 `json:"dup,omitempty"` // bytes that arrived twice
}

// BondStater is a wire made of legs that can say what each carried.
type BondStater interface{ BondStats() []BondLegStat }

// BondStats reports each leg, in the link's order.
func (w *bondWire) BondStats() []BondLegStat {
	out := make([]BondLegStat, len(w.legs))
	for i, l := range w.legs {
		out[i] = BondLegStat{Leg: l.Spec().ID}
		if i < len(w.stats) {
			c := &w.stats[i]
			out[i].Down, out[i].Up = c.down.Load(), c.up.Load()
			out[i].Drops, out[i].Backs, out[i].Fails = c.drops.Load(), c.backs.Load(), c.fails.Load()
			out[i].Rests, out[i].Hedges, out[i].Retx = c.rests.Load(), c.hedges.Load(), c.retx.Load()
			out[i].RTT, out[i].MinRTT, out[i].Ms = c.rtt.Load(), c.minRTT.Load(), c.durMs.Load()
			c.mu.Lock()
			if len(c.why) > 0 {
				out[i].Why = make(map[string]int64, len(c.why))
				for k, v := range c.why {
					out[i].Why[k] = v
				}
			}
			c.mu.Unlock()
		}
	}
	if w.holes.Load() > 0 || w.dup.Load() > 0 {
		out = append(out, BondLegStat{Leg: "*", Holes: w.holes.Load(), HoleMs: w.holeMs.Load(),
			HoleMax: w.holeMax.Load(), OOOMax: w.oooMax.Load(), Dup: w.dup.Load()})
	}
	return out
}

// flowEnded takes in a finished flow's bond counts.
func (w *bondWire) flowEnded(st kilvater.BondStats) {
	w.holes.Add(int64(st.Holes))
	w.holeMs.Add(st.HoleWait.Milliseconds())
	w.dup.Add(int64(st.DupBytes))
	if v := st.HoleMax.Milliseconds(); v > w.holeMax.Load() {
		w.holeMax.Store(v)
	}
	if v := int64(st.OOOMax); v > w.oooMax.Load() {
		w.oooMax.Store(v)
	}
}

func (w *bondWire) count(i int) *legCount {
	if i < len(w.stats) {
		return &w.stats[i]
	}
	return nil
}

// countedLeg counts a leg's bytes into its legCount.
type countedLeg struct {
	net.Conn
	c *legCount
}

func (l countedLeg) Read(p []byte) (int, error) {
	n, err := l.Conn.Read(p)
	l.c.down.Add(int64(n))
	return n, err
}

func (l countedLeg) Write(p []byte) (int, error) {
	n, err := l.Conn.Write(p)
	l.c.up.Add(int64(n))
	return n, err
}

// bondTune is how a bond's legs are kept up (see bondLegRetry).
type bondTune struct {
	retry, retryMax       time.Duration
	tries, rejoins, alone int
}

func (w *bondWire) tuning() bondTune {
	if w.tune != nil {
		return *w.tune
	}
	return bondTune{bondLegRetry, bondLegRetryMax, bondLegTries, bondLegRejoins, bondLegRejoinsAlone}
}

// bondLegRest is how long a leg that never got into a flow is left alone by the
// flows that follow, doubling up to bondLegRestMax while it keeps failing. Off
// the mobile networks the CDN leg's door answers every flow with its cover
// site: without the rest each flow knocks on it bondLegTries+1 times, on the
// port the bond is there to spare. A flow that outlives the rest tries the leg
// then; a leg that got in rests no more.
var (
	bondLegRest    = 20 * time.Second
	bondLegRestMax = 2 * time.Minute
)

// resting is how much longer leg i is left alone.
func (w *bondWire) resting(i int) time.Duration {
	if i >= len(w.restTill) {
		return 0
	}
	return time.Until(time.UnixMilli(w.restTill[i].Load()))
}

// rested notes how leg i's tries in a flow ended: in (it carried) or never in.
func (w *bondWire) rested(i int, in bool) {
	if i >= len(w.restTill) {
		return
	}
	if in {
		w.restFor[i].Store(0)
		w.restTill[i].Store(0)
		return
	}
	d := time.Duration(w.restFor[i].Load()) * 2
	if d < bondLegRest {
		d = bondLegRest
	}
	if d > bondLegRestMax {
		d = bondLegRestMax
	}
	w.restFor[i].Store(int64(d))
	w.restTill[i].Store(time.Now().Add(d).UnixMilli())
}

func newBond(s PathSpec) (Wire, error) {
	ws := make([]*kilWire, 0, len(s.Legs))
	for _, ls := range s.Legs {
		ls := ls
		w, err := newKilWire(ls, func(ctx context.Context) (net.Conn, error) {
			return dialSecure(ctx, ls, false)
		})
		if err != nil {
			for _, o := range ws {
				o.Close()
			}
			return nil, err
		}
		ws = append(ws, w)
	}
	return &bondWire{spec: s, legs: ws, stats: make([]legCount, len(ws)),
		restTill: make([]atomic.Int64, len(ws)), restFor: make([]atomic.Int64, len(ws))}, nil
}

func (w *bondWire) ID() string           { return w.spec.ID }
func (w *bondWire) Spec() PathSpec       { return w.spec }
func (w *bondWire) NeedsHandshake() bool { return w.legs[0].NeedsHandshake() }

func (w *bondWire) Close() error {
	for _, l := range w.legs {
		l.Close()
	}
	return nil
}

func (w *bondWire) Refresh(t time.Time) {
	for _, l := range w.legs {
		l.Refresh(t)
	}
}

// Dial opens the first leg that opens; the others open when the flow starts.
func (w *bondWire) Dial(ctx context.Context) (Session, error) {
	var last error
	// The legs that are not resting first, then the resting ones: a flow
	// never fails for a rest.
	for _, rest := range []bool{false, true} {
		for i, l := range w.legs {
			if (w.resting(i) > 0) != rest {
				continue
			}
			st, err := l.openTunnel(ctx)
			if err == nil {
				return &bondSession{w: w, first: st, firstLeg: i}, nil
			}
			last = err
			if ctx.Err() != nil {
				return nil, last
			}
		}
	}
	return nil, last
}

// DialPacket: UDP rides the first leg alone.
func (w *bondWire) DialPacket(ctx context.Context) (PacketSession, error) {
	return w.legs[0].DialPacket(ctx)
}

var _ PacketWire = (*bondWire)(nil)

type bondSession struct {
	w        *bondWire
	first    net.Conn
	firstLeg int
	once     sync.Once
}

func (s *bondSession) Close() error {
	s.once.Do(func() { s.first.Close() })
	return nil
}

// Defaults for bondTune. bondLegRetry is how long a dead leg waits before it is opened again, and
// bondLegTries how many times in a row it may fail before it is let go when
// it never got in. A leg that has carried the flow is opened again after a
// drop (a route that blinks comes back into the flow), the pause doubling up to
// bondLegRetryMax, bondLegRejoins times in a row, or bondLegRejoinsAlone when no
// other leg is carrying (the server may have lost the bond: the flow should
// fail, not hang). bondLegRejoins = 12 keeps a leg trying for ~79 s
// (1+2+4+8×9): a VK TURN leg cut for even 10 s only comes back once vkturn
// gives its silent tunnel up (giveUp 40 s) and opens a fresh one; with 6
// (~31 s) the leg let go just before that (measured from NSK 16.11).
const (
	bondLegRetry        = time.Second
	bondLegRetryMax     = 8 * time.Second
	bondLegTries        = 4
	bondLegRejoins      = 12
	bondLegRejoinsAlone = 2
)

func (s *bondSession) Run(ctx context.Context, target Target, prelude []byte, up <-chan []byte, down io.Writer, m Meter) (Outcome, error) {
	var sid [kilvater.SessionIDLen]byte
	rand.Read(sid[:])
	join := func(create bool) ([]byte, error) {
		var f byte
		if create {
			f = kilvater.JoinCreate
		}
		return kilvater.AppendJoin(nil, sid, f, kilvater.NetTCP, target.String())
	}
	if _, err := join(true); err != nil {
		s.Close()
		return OutcomeError, err
	}
	b := kilvater.NewBond()
	b.OnLegEnd = func(st kilvater.LegStats) {
		if i, err := strconv.Atoi(st.Name); err == nil {
			if lc := s.w.count(i); lc != nil {
				lc.ended(st)
			}
		}
	}
	defer func() { s.w.flowEnded(b.Stats()) }()
	tn := s.w.tuning()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Each leg is kept up while the flow lives: opened, joined, carried until
	// it fails, opened again after a pause, also after it failed to reopen
	// (see bondLegRejoins). A leg the server never answered on (a server
	// without bonds, a refused key) is let go after bondLegTries.
	var legsWG sync.WaitGroup
	alive := make(chan struct{}, len(s.w.legs)) // a leg ended
	everUp := make(chan struct{})
	var everOnce sync.Once
	for i := range s.w.legs {
		i := i
		legsWG.Add(1)
		go func() {
			defer legsWG.Done()
			defer func() { alive <- struct{}{} }()
			create, fails, pause := true, 0, tn.retry
			if d := s.w.resting(i); d > 0 && i != s.firstLeg {
				select { // the leg failed the flows before this one: it joins when its rest is over
				case <-ctx.Done():
					return
				case <-time.After(d):
				}
			}
			for ctx.Err() == nil && !b.Done() {
				var st net.Conn
				var err error
				if i == s.firstLeg && create {
					st = s.first
				} else {
					st, err = s.w.legs[i].openTunnel(ctx)
				}
				accepted := false
				lc := s.w.count(i)
				if err != nil && lc != nil && ctx.Err() == nil {
					lc.cause("open:"+kilvater.ErrClass(err), 1)
				}
				if err == nil {
					if lc != nil {
						st = countedLeg{st, lc}
					}
					body, _ := join(create)
					if err = kilvater.WriteFrame(st, kilvater.FrameJoin, body); err == nil {
						accepted = b.RunLegNamed(st, false, strconv.Itoa(i))
					} else {
						if lc != nil {
							lc.cause("join:"+kilvater.ErrClass(err), 1)
						}
						st.Close()
					}
				}
				if accepted {
					everOnce.Do(func() { close(everUp) })
					if lc != nil {
						if !create {
							lc.backs.Add(1)
						}
						if ctx.Err() == nil && !b.Done() {
							lc.drops.Add(1) // it carried and fell out while the flow lives
						}
					}
					if create {
						s.w.rested(i, true)
					}
					create, fails, pause = false, 0, tn.retry
				} else {
					if lc != nil {
						lc.fails.Add(1)
					}
					fails++
					switch {
					case create && fails > tn.tries: // never got in: a refused key, a server without bonds
						if ctx.Err() == nil && !b.Done() {
							s.w.rested(i, false)
						}
						return
					case !create && (fails > tn.rejoins || b.Legs() == 0 && fails > tn.alone):
						return
					}
					if !create {
						if pause *= 2; pause > tn.retryMax {
							pause = tn.retryMax
						}
					}
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(pause):
				}
			}
		}()
	}
	// The flow fails when every leg has given up.
	go func() {
		for n := 0; n < len(s.w.legs); n++ {
			select {
			case <-alive:
			case <-ctx.Done():
				return
			}
		}
		b.Abort(1, ErrWireDead)
	}()
	defer func() {
		b.Close()
		cancel()
		legsWG.Wait()
	}()

	if len(prelude) > 0 {
		if _, err := b.Write(prelude); err != nil {
			return OutcomeError, err
		}
	}
	it := newIdleTimer(IdleTimeout, cancel)
	defer it.stop()
	go func() {
		<-ctx.Done()
		b.Abort(0, ctx.Err()) // unblocks the downstream reader; the far end just closes
	}()
	upErr := make(chan error, 1)
	go func() { upErr <- pumpUp(ctx, up, b, m, it) }()
	downErr := make(chan error, 1)
	go func() {
		err := pumpDown(b, down, m, it)
		if err != nil {
			select {
			case <-everUp:
			default:
				err = ErrWireDead // no leg ever got through: the path is dead, not the flow
			}
		}
		downErr <- err
	}()
	return settle(ctx, upErr, downErr, cancel, func() {
		it.setTimeout(2 * time.Second)
		b.CloseWrite()
	})
}
