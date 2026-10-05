// Package sim is a deterministic simulator of paths, destinations and the local
// network. It runs the same workload through farvater-core and through the
// latency baseline so that the difference is measurable before any real code.
package sim

import (
	"math/rand/v2"
	"sort"

	"github.com/tsyrenov1987/farvater-core/brain"
)

// PathModel describes how one path behaves.
type PathModel struct {
	ID, SNI, IP  string
	Rail         string // protocol family label, for escape-diversity
	RTTMs        int64
	CutAtBytes   int64 // 0 = carries everything; else the stream stalls after this many bytes (throttle/shaping)
	OnsetMs      int64 // the cut applies from this time on (0 = always)
	GoodputBps   int64
	WireFailProb float64

	// TSPU impairments that switch on at a time (0 = never):
	ResetAtBytes  int64 // after ResetOnsetMs, a flow past this many bytes is RST mid-stream
	ResetOnsetMs  int64
	BlackholeFrom int64 // from this time the path connects but delivers no first byte
}

// Network models the local network: outages and the behavioural-freeze hypothesis.
type Network struct {
	FreezeRule      bool  // >FreezeThreshold handshakes to one SNI inside FreezeWindowMs → freeze FreezeMs
	FreezeWindowMs  int64 // 350
	FreezeThreshold int   // 3
	FreezeMs        int64 // 120000
	Down            [][2]int64

	hs          map[string][]int64
	frozenUntil map[string]int64
	Freezes     int
}

func (n *Network) init() {
	if n.hs == nil {
		n.hs = map[string][]int64{}
		n.frozenUntil = map[string]int64{}
	}
	if n.FreezeWindowMs == 0 {
		n.FreezeWindowMs = 350
	}
	if n.FreezeThreshold == 0 {
		n.FreezeThreshold = 3
	}
	if n.FreezeMs == 0 {
		n.FreezeMs = 120_000
	}
}

// Handshake records a TLS handshake to sni at time at and reports whether it is frozen.
func (n *Network) Handshake(sni string, at int64) bool {
	n.init()
	n.hs[sni] = append(n.hs[sni], at)
	if !n.FreezeRule {
		return false
	}
	cnt := 0
	for _, t := range n.hs[sni] {
		if t > at-n.FreezeWindowMs && t <= at {
			cnt++
		}
	}
	if cnt > n.FreezeThreshold && at >= n.frozenUntil[sni] {
		n.frozenUntil[sni] = at + n.FreezeMs
		n.Freezes++
	}
	return at < n.frozenUntil[sni]
}

// Handshakes returns the sorted handshake log per SNI.
func (n *Network) Handshakes() map[string][]int64 {
	n.init()
	out := map[string][]int64{}
	for k, v := range n.hs {
		c := append([]int64(nil), v...)
		sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
		out[k] = c
	}
	return out
}

// IsDown reports whether the local network is out at time at.
func (n *Network) IsDown(at int64) bool {
	for _, w := range n.Down {
		if at >= w[0] && at < w[1] {
			return true
		}
	}
	return false
}

// Workload describes the flow generator.
type Workload struct {
	N           int
	DurationMs  int64
	BurstProb   float64 // probability that an arrival is a page load of BurstSize flows
	BurstSize   int
	DeadDstProb float64 // share of flows to a dead destination
}

// Flow is one connection request from a local app.
type Flow struct {
	ID        int
	StartMs   int64
	WantBytes int64
	Dst       string
	Class     brain.DstClass
	Dead      bool
}

// Scenario bundles everything a run needs.
type Scenario struct {
	Name  string
	Paths []PathModel
	Net   Network
	Work  Workload
	Seed  uint64
}

// GenerateWorkload produces the flows of a scenario deterministically.
func GenerateWorkload(w Workload, rng *rand.Rand) []Flow {
	rate := float64(w.N) / float64(w.DurationMs)
	t := 0.0
	var flows []Flow
	id := 0
	for id < w.N {
		t += rng.ExpFloat64() / rate
		if int64(t) >= w.DurationMs {
			break
		}
		k := 1
		if w.BurstSize > 1 && rng.Float64() < w.BurstProb {
			k = w.BurstSize
		}
		for j := 0; j < k && id < w.N; j++ {
			flows = append(flows, makeFlow(id, int64(t)+int64(j)*15, w, rng))
			id++
		}
	}
	sort.SliceStable(flows, func(i, j int) bool { return flows[i].StartMs < flows[j].StartMs })
	return flows
}

func makeFlow(id int, start int64, w Workload, rng *rand.Rand) Flow {
	f := Flow{ID: id, StartMs: start}
	u := rng.Float64()
	switch {
	case u < 0.4:
		f.WantBytes = 512 + int64(rng.IntN(12*1024))
		if rng.Float64() < 0.3 {
			f.Class = brain.DstDNS
		} else {
			f.Class = brain.DstTLS443
		}
	case u < 0.8:
		f.WantBytes = 16*1024 + int64(rng.IntN(224*1024))
		f.Class = brain.DstTLS443
	default:
		f.WantBytes = 300*1024 + int64(rng.IntN(2700*1024))
		f.Class = brain.DstTLS443
	}
	h := rng.IntN(50)
	if w.DeadDstProb > 0 && rng.Float64() < w.DeadDstProb {
		f.Dead = true
		f.Dst = "dead-" + itoa(h%3)
	} else {
		f.Dst = "host-" + itoa(h)
	}
	return f
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
