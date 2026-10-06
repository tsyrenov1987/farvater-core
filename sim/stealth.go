package sim

import (
	"sort"

	"github.com/tsyrenov1987/farvater-core/brain"
)

// Exposure is what an observer of the client's connections can count: how much
// of the fan it touches, and whether a failure lights up a server it had not
// seen.
type Exposure struct {
	ServersPerHour   float64 // distinct server addresses dialled in an hour, on average
	TunnelsPer10Min  float64 // distinct paths dialled in ten minutes, on average
	ExplorePerHour   float64 // dials that measure a path rather than serve the leader
	FailedPerHour    float64 // dials met with silence, a reset or a stall
	RevealsPerHour   float64 // failures followed within a second by a dial to a server unseen for ten minutes
	NotHTTPAfterFail float64 // per hour: failures followed within a second by a dial to a path that looks like no HTTP
}

const (
	hourMs         = 60 * minuteMs
	minuteMs       = int64(60_000)
	revealWindowMs = 1000
	unseenMs       = 10 * minuteMs
)

// Measure counts the exposure of a run over [0, endMs), endMs a whole number of hours.
func Measure(res Result, paths []PathModel, endMs int64) Exposure {
	server, notHTTP := map[string]string{}, map[string]bool{}
	for _, p := range paths {
		server[p.ID], notHTTP[p.ID] = p.IP, p.NotHTTP
	}
	dials := append([]Dial(nil), res.Dials...)
	sort.Slice(dials, func(i, j int) bool { return dials[i].At < dials[j].At })
	times := map[string][]int64{} // server → dial starts, in order
	hours, tens := map[int64]map[string]bool{}, map[int64]map[string]bool{}
	explore, failed, reveals, lit := 0, 0, 0, 0
	for _, d := range dials {
		s := server[d.Path]
		times[s] = append(times[s], d.At)
		if h := d.At / hourMs; hours[h] == nil {
			hours[h] = map[string]bool{}
		}
		hours[d.At/hourMs][s] = true
		if w := d.At / (10 * minuteMs); tens[w] == nil {
			tens[w] = map[string]bool{}
		}
		tens[d.At/(10*minuteMs)][d.Path] = true
		if d.Explore {
			explore++
		}
	}
	seen := func(s string, from, to int64) bool {
		ts := times[s]
		i := sort.Search(len(ts), func(i int) bool { return ts[i] >= from })
		return i < len(ts) && ts[i] <= to
	}
	for _, d := range dials {
		if d.OK {
			continue
		}
		failed++
		t := d.EndAt
		revealed, nh := false, false
		for j := sort.Search(len(dials), func(i int) bool { return dials[i].At > t }); j < len(dials) && dials[j].At <= t+revealWindowMs; j++ {
			if s := server[dials[j].Path]; s != server[d.Path] && !seen(s, t-unseenMs, t) {
				revealed = true
			}
			nh = nh || notHTTP[dials[j].Path]
		}
		if revealed {
			reveals++
		}
		if nh {
			lit++
		}
	}
	n := float64(endMs) / float64(hourMs)
	return Exposure{ServersPerHour: float64(distinct(hours)) / n, TunnelsPer10Min: float64(distinct(tens)) / float64(len(tens)),
		ExplorePerHour: float64(explore) / n, FailedPerHour: float64(failed) / n, RevealsPerHour: float64(reveals) / n,
		NotHTTPAfterFail: float64(lit) / n}
}

func distinct(windows map[int64]map[string]bool) int {
	n := 0
	for _, w := range windows {
		n += len(w)
	}
	return n
}

// ChromeConfig is the brain's configuration under the browser-like prototype:
// a path's guaranteed flow every 30 minutes instead of 10, and a quarter of the
// exploration share.
func ChromeConfig() brain.Config {
	cfg := brain.DefaultConfig()
	cfg.ExploreShare = 0.05
	cfg.FloorMs = 30 * minuteMs
	return cfg
}

const (
	altSvcMs     = 30 * minuteMs // a delivery over TCP vouches for the server's QUIC this long
	quicBrokenMs = 5 * minuteMs  // after QUIC fails on a server, TCP alone there this long
)

// ChromePolicy is a prototype, for the simulator only, of a client that behaves
// like a browser. A flow that gets no answer is retried on its server only.
// QUIC is used only on a server whose TCP path delivered lately, and not while
// QUIC there has just failed. Exploration is rarer (ChromeConfig).
type ChromePolicy struct {
	B      *brain.Brain
	paths  map[string]PathModel
	tcpOK  map[string]int64 // server → last delivery over TCP there
	quicNo map[string]int64 // server → no QUIC there before this
}

func NewChromePolicy(b *brain.Brain, paths []PathModel) *ChromePolicy {
	p := &ChromePolicy{B: b, paths: map[string]PathModel{}, tcpOK: map[string]int64{}, quicNo: map[string]int64{}}
	for _, m := range paths {
		p.paths[m.ID] = m
	}
	return p
}

func (p *ChromePolicy) Name() string { return "chrome" }

func quic(m PathModel) bool { return m.Rail == "hy2" }

// usable: TCP always; QUIC where TCP delivered lately and QUIC has not just failed.
func (p *ChromePolicy) usable(id string, now int64) bool {
	m := p.paths[id]
	if !quic(m) {
		return true
	}
	at := p.tcpOK[m.IP]
	return at > 0 && now-at <= altSvcMs && now >= p.quicNo[m.IP]
}

// sameServer is the best usable path on id's server other than id, in the
// brain's order, skipping those it avoids.
func (p *ChromePolicy) sameServer(id string, now int64) string {
	ip := p.paths[id].IP
	for _, c := range p.B.UDPOrder(now) {
		if c != id && p.paths[c].IP == ip && p.usable(c, now) && !p.B.Breaker.Tripped(c, now) && !p.B.Diag.Parked(c, now) {
			return c
		}
	}
	return ""
}

func (p *ChromePolicy) Pick(now int64, dst string, class brain.DstClass) brain.Decision {
	d := p.B.Pick(now, dst, class)
	if !p.usable(d.Primary, now) {
		if alt := p.sameServer(d.Primary, now); alt != "" {
			d.Primary = alt
		}
	}
	d.Secondary = p.sameServer(d.Primary, now) // the runner dials no third
	return d
}

func (p *ChromePolicy) Observe(r brain.Receipt) {
	p.B.Observe(r)
	m := p.paths[r.Path]
	switch {
	case !quic(m) && r.Delivered():
		p.tcpOK[m.IP] = r.AtMs
	case quic(m) && !r.FirstByte():
		p.quicNo[m.IP] = r.AtMs + quicBrokenMs
	}
}
