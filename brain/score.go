package brain

import (
	"math"
	"math/rand/v2"
	"sort"
)

// PathState is the evidence a brain holds about one path in one network context.
type PathState struct {
	evDelivA, evDelivB float64 // decayed evidence counts
	evFbA, evFbB       float64
	priorDelivA        float64 // weak prior pseudo-counts (already weighted and capped)
	priorDelivB        float64
	GoodputBps         float64
	Cut16              bool
	failBytes          []int64
	bigOK              int
	LastEvidenceMs     int64
	lastDecayMs        int64
	fbTimes            []int64
	recent             []int64
	stallRun           int
	Receipts           int
	Served             int // receipts whose first byte came with no block signature
	Blocked            int // receipts with a block signature; the rest closed before any answer
}

// MaxPriorWeight caps prior pseudo-counts so that five fresh receipts outweigh them.
const MaxPriorWeight = 4.0

// SetDelivPrior installs a weak delivery prior: Beta(a, b) scaled by weight and capped.
func (s *PathState) SetDelivPrior(a, b, weight float64) {
	if a < 0 || b < 0 || weight <= 0 {
		return
	}
	a, b = a*weight, b*weight
	if t := a + b; t > MaxPriorWeight {
		a, b = a*MaxPriorWeight/t, b*MaxPriorWeight/t
	}
	s.priorDelivA, s.priorDelivB = a, b
}

func (s *PathState) decay(now, halfLifeMs int64) {
	if s.lastDecayMs == 0 {
		s.lastDecayMs = now
		return
	}
	dt := now - s.lastDecayMs
	if dt <= 0 || halfLifeMs <= 0 {
		return
	}
	f := math.Pow(0.5, float64(dt)/float64(halfLifeMs))
	s.evDelivA *= f
	s.evDelivB *= f
	s.evFbA *= f
	s.evFbB *= f
	s.lastDecayMs = now
}

// Observe folds one receipt into the state.
func (s *PathState) Observe(r Receipt, now, halfLifeMs int64) {
	s.decay(now, halfLifeMs)
	s.Receipts++
	switch {
	case r.Sig() != SigNone:
		s.Blocked++
	case r.FirstByte():
		s.Served++
	}
	dv := r.DelivEvidence()
	switch dv {
	case 1:
		s.evDelivA++
	case -1:
		s.evDelivB++
	}
	switch r.FbEvidence() {
	case 1:
		s.evFbA++
	case -1:
		s.evFbB++
	}
	if r.FirstByte() {
		s.fbTimes = append(s.fbTimes, r.FirstByteMs)
		if len(s.fbTimes) > 20 {
			s.fbTimes = s.fbTimes[1:]
		}
	}
	if dv == -1 && r.DownAtFail >= 0 {
		s.failBytes = append(s.failBytes, r.DownAtFail)
		if len(s.failBytes) > 6 {
			s.failBytes = s.failBytes[1:]
		}
		if len(s.failBytes) >= 3 {
			if m := median(s.failBytes); m >= Cut16Lo && m <= Cut16Hi {
				s.Cut16 = true
				s.bigOK = 0
			}
		}
	}
	if r.Delivered() && r.Down >= 64*KB {
		s.bigOK++
		if s.bigOK >= 3 && s.Cut16 {
			s.Cut16 = false
			s.failBytes = nil
		}
	} else if dv == -1 {
		s.bigOK = 0
	}
	if r.Delivered() && r.Down > BigBytes && r.DurMs > 0 {
		bps := float64(r.Down) * 1000 / float64(r.DurMs)
		if s.GoodputBps == 0 {
			s.GoodputBps = bps
		} else {
			s.GoodputBps = 0.7*s.GoodputBps + 0.3*bps
		}
	}
	if r.Stalls > 0 {
		s.stallRun++
	} else if dv == 1 {
		s.stallRun = 0
	}
	s.LastEvidenceMs = now
	s.recent = append(s.recent, now)
}

func median(v []int64) int64 {
	c := append([]int64(nil), v...)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	return c[len(c)/2]
}

// DelivPosterior returns Beta(a, b) parameters for "a ≥16 KB flow completes without a stall".
func (s PathState) DelivPosterior() (a, b float64) {
	return 1 + s.priorDelivA + s.evDelivA, 1 + s.priorDelivB + s.evDelivB
}

// FbPosterior returns Beta(a, b) parameters for "the first byte arrives in time".
func (s PathState) FbPosterior() (a, b float64) { return 1 + s.evFbA, 1 + s.evFbB }

// DelivMean and FbMean are posterior means.
func (s PathState) DelivMean() float64 { a, b := s.DelivPosterior(); return a / (a + b) }
func (s PathState) FbMean() float64    { a, b := s.FbPosterior(); return a / (a + b) }

// Mean is the expected probability that a new flow is served: deliv × first byte.
func (s PathState) Mean() float64 { return s.DelivMean() * s.FbMean() }

// Sample draws one Thompson sample of the same quantity.
func (s PathState) Sample(rng *rand.Rand) float64 {
	da, db := s.DelivPosterior()
	fa, fb := s.FbPosterior()
	return BetaSample(rng, da, db) * BetaSample(rng, fa, fb)
}

// RecentReceipts counts receipts inside the trailing window.
func (s *PathState) RecentReceipts(now, windowMs int64) int {
	i := 0
	for i < len(s.recent) && s.recent[i] < now-windowMs {
		i++
	}
	s.recent = s.recent[i:]
	return len(s.recent)
}

// P90FirstByteMs is the 90th percentile of observed first-byte times (1200 ms until 5 samples).
func (s PathState) P90FirstByteMs() int64 {
	if len(s.fbTimes) < 5 {
		return 1200
	}
	c := append([]int64(nil), s.fbTimes...)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	return c[(len(c)*9)/10]
}

// ConsecutiveStalls is the current run of stalled flows; ResetStalls clears it.
func (s PathState) ConsecutiveStalls() int { return s.stallRun }
func (s *PathState) ResetStalls()          { s.stallRun = 0 }
