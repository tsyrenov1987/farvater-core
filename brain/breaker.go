package brain

// breaker.go — the anti-TSPU circuit breaker.
//
// The posterior/Thompson layer learns slowly and on purpose: it must not flap
// on noise. But a DPI box (TSPU) does not produce noise — it produces sharp,
// recognisable damage: injected RST mid-stream, a silent black hole after the
// handshake, a sudden goodput collapse, dropped SYNs. Waiting for five receipts
// and two consecutive stalls to react to that is too slow.
//
// The breaker makes the response ASYMMETRIC: promotion stays slow (the
// posterior gate in brain.go is untouched), demotion is immediate. One
// unambiguous block signature on a rail trips it at once; the rail is then
// avoided as a PRIMARY for a signature-dependent cooldown and the leader, if it
// was the one tripped, is dethroned on the spot.
//
// This is NOT narrowing the fan. The trip is client-side, per-user, reactive to
// measured delivery, and ALWAYS time-boxed: when the cooldown expires the rail
// re-enters selection and the exploration floor re-probes it. No rail is ever
// removed. It is the client-side mirror of the owner's no-narrowing rule: we
// heal a suffering user by ADDING live re-measurement across rails (storm mode),
// never by permanently taking a rail away.

// BlockSig is the kind of damage a receipt reveals.
type BlockSig int

const (
	SigNone      BlockSig = iota
	SigReset              // RST mid-stream (often with the cut16 fingerprint): active DPI reset
	SigHandshake          // failed before the wire was ready: dropped SYN / reset on connect / freeze
	SigBlackhole          // wire connected, no first byte, then timed out: silent drop after handshake
	SigThrottle           // first byte arrived, then goodput collapsed or stalled: shaping
)

func (s BlockSig) String() string {
	switch s {
	case SigReset:
		return "reset"
	case SigHandshake:
		return "handshake"
	case SigBlackhole:
		return "blackhole"
	case SigThrottle:
		return "throttle"
	}
	return "none"
}

// Hard reports whether a single occurrence of this signature trips a rail.
// A reset is unambiguous DPI action, so one is enough; the softer signatures
// can be transient and need to repeat inside the window.
func (s BlockSig) Hard() bool { return s == SigReset }

// classify reads the block signature out of a receipt.
func classify(r Receipt) BlockSig {
	if r.WireReadyMs < 0 {
		switch r.End {
		case EndWireReset, EndTimeout:
			return SigHandshake
		}
		return SigNone
	}
	if !r.FirstByte() {
		switch r.End {
		case EndWireReset, EndTimeout, EndStallAbandon:
			return SigBlackhole
		}
		return SigNone
	}
	switch r.End {
	case EndWireReset:
		return SigReset
	case EndStallAbandon:
		return SigThrottle
	case EndTimeout:
		return SigThrottle
	}
	if r.Stalls > 0 {
		return SigThrottle
	}
	return SigNone
}

// BreakerConfig holds the breaker thresholds. All numbers are hypotheses to be
// calibrated against a real RU cohort; they are deliberately conservative so
// the breaker never fights the slow learner on ordinary jitter.
type BreakerConfig struct {
	Enabled      bool               // master switch (off = pure slow learner, for ablation)
	WindowMs     int64              // counting / turbulence window
	SoftTrips    int                // soft signals inside the window that trip a rail
	Cooldown     map[BlockSig]int64 // per-signature avoid-as-primary duration
	StormRails   int                // distinct tripped rails in the window that raise storm mode
	StormExplore float64            // exploration share cap while a storm lasts
	StormFanout  bool               // dial a third, diverse rail while a storm lasts
}

// DefaultBreakerConfig returns the design defaults.
func DefaultBreakerConfig() BreakerConfig {
	return BreakerConfig{
		Enabled:   true,
		WindowMs:  60_000,
		SoftTrips: 2,
		Cooldown: map[BlockSig]int64{
			SigReset:     90_000,
			SigBlackhole: 60_000,
			SigHandshake: 45_000,
			SigThrottle:  30_000,
		},
		StormRails:   2,
		StormExplore: 0.6,
		StormFanout:  true,
	}
}

type tripEvent struct {
	at  int64
	sig BlockSig
}

type railBreaker struct {
	trippedUntil int64
	sig          BlockSig
	soft         []tripEvent // soft signals still inside the window
}

// Breaker tracks block signatures per rail and across the fleet.
type Breaker struct {
	cfg   BreakerConfig
	rails map[string]*railBreaker
	trips []tripEvent // fleet-wide trips, for storm detection
}

// NewBreaker builds a breaker.
func NewBreaker(cfg BreakerConfig) *Breaker {
	return &Breaker{cfg: cfg, rails: map[string]*railBreaker{}}
}

func (b *Breaker) rail(path string) *railBreaker {
	r := b.rails[path]
	if r == nil {
		r = &railBreaker{}
		b.rails[path] = r
	}
	return r
}

// Note folds one receipt in and reports whether it tripped the rail, and on
// which signature. A delivered flow clears the rail's soft history.
func (b *Breaker) Note(r Receipt, now int64) (bool, BlockSig) {
	sig := classify(r)
	if !b.cfg.Enabled {
		return false, sig
	}
	rb := b.rail(r.Path)
	if sig == SigNone {
		rb.soft = rb.soft[:0]
		return false, SigNone
	}
	trip := false
	if sig.Hard() {
		trip = true
	} else {
		cut := now - b.cfg.WindowMs
		kept := rb.soft[:0]
		for _, e := range rb.soft {
			if e.at >= cut {
				kept = append(kept, e)
			}
		}
		rb.soft = append(kept, tripEvent{now, sig})
		if len(rb.soft) >= b.cfg.SoftTrips {
			trip = true
		}
	}
	if !trip {
		return false, sig
	}
	cd := b.cfg.Cooldown[sig]
	if cd == 0 {
		cd = 30_000
	}
	rb.trippedUntil = now + cd
	rb.sig = sig
	rb.soft = rb.soft[:0]
	b.trips = append(b.trips, tripEvent{now, sig})
	b.pruneTrips(now)
	return true, sig
}

func (b *Breaker) pruneTrips(now int64) {
	cut := now - b.cfg.WindowMs
	i := 0
	for i < len(b.trips) && b.trips[i].at < cut {
		i++
	}
	b.trips = b.trips[i:]
}

// Tripped reports whether a rail is currently avoided as a primary.
func (b *Breaker) Tripped(path string, now int64) bool {
	if !b.cfg.Enabled {
		return false
	}
	r := b.rails[path]
	return r != nil && now < r.trippedUntil
}

// TrippedSig returns the signature a rail tripped on (SigNone if not tripped).
func (b *Breaker) TrippedSig(path string, now int64) BlockSig {
	if !b.Tripped(path, now) {
		return SigNone
	}
	return b.rails[path].sig
}

// Storm reports an active fleet-wide disturbance: several distinct rails tripped
// inside the window. During a storm the brain re-measures delivery across rails
// in parallel instead of leaning on one leader.
func (b *Breaker) Storm(now int64) bool {
	if !b.cfg.Enabled {
		return false
	}
	b.pruneTrips(now)
	// Count distinct rails among recent trips by timestamp clustering is not
	// needed: trips are already fleet-wide events; distinctness is enforced by
	// callers tripping each rail at most once per cooldown.
	return len(b.trips) >= b.cfg.StormRails
}
