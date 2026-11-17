package kilvater

import (
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// bondMetrics is what the bonds did, by the route a leg came by (the host of
// its request): the CDN's name for the leg through the CDN, the node's own
// for the leg through the TURN relays. Everything here is from the server's
// end: "sent" is towards the client.
type bondMetrics struct {
	mu     sync.Mutex
	routes map[string]*bondRoute
	bonds  int64 // ended
	dup    uint64
	holes  int64
	holeMs int64
	// the worst of the bonds ended in the present and the last five minutes
	maxAt            time.Time
	holeMax, holeOld int64
	oooMax, oooOld   int64
}

type bondRoute struct {
	legs, open           int64
	sent, rcvd           uint64
	rests, hedges, retx  int64
	rttMs, minRttMs, rtN int64 // sums over the legs that measured one
	durMs                int64
	ends                 map[string]int64
}

// maxBondRoutes caps the routes kept apart: the host is the client's to say.
const maxBondRoutes = 12

func bondRouteName(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	if host == "" || len(host) > 64 || strings.ContainsAny(host, "\"\\\n{} ") {
		return "other"
	}
	return host
}

func (m *bondMetrics) route(host string) *bondRoute {
	name := bondRouteName(host)
	if m.routes == nil {
		m.routes = map[string]*bondRoute{}
	}
	r := m.routes[name]
	if r == nil {
		if len(m.routes) >= maxBondRoutes {
			name = "other"
			if r = m.routes[name]; r != nil {
				return r
			}
		}
		r = &bondRoute{ends: map[string]int64{}}
		m.routes[name] = r
	}
	return r
}

func (m *Metrics) bondRefused(route, why string) {
	if m == nil {
		return
	}
	m.bond.mu.Lock()
	m.bond.route(route).ends["refused:"+why]++
	m.bond.mu.Unlock()
}

func (m *Metrics) bondLegStart(route string) {
	if m == nil {
		return
	}
	m.bond.mu.Lock()
	r := m.bond.route(route)
	r.legs++
	r.open++
	m.bond.mu.Unlock()
}

func (m *Metrics) bondLegEnd(st LegStats) {
	if m == nil {
		return
	}
	m.bond.mu.Lock()
	defer m.bond.mu.Unlock()
	r := m.bond.route(st.Name)
	r.open--
	r.sent += st.Sent
	r.rcvd += st.Rcvd
	r.rests += int64(st.Rests)
	r.hedges += int64(st.Hedges)
	r.retx += int64(st.Retx)
	r.durMs += st.Dur.Milliseconds()
	if st.RTT > 0 {
		r.rttMs += st.RTT.Milliseconds()
		r.minRttMs += st.MinRTT.Milliseconds()
		r.rtN++
	}
	for k, v := range st.Ends {
		r.ends[k] += int64(v)
	}
}

func (m *Metrics) bondEnd(st BondStats) {
	if m == nil {
		return
	}
	b := &m.bond
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bonds++
	b.dup += st.DupBytes
	b.holes += int64(st.Holes)
	b.holeMs += st.HoleWait.Milliseconds()
	b.rollLocked(time.Now())
	if v := st.HoleMax.Milliseconds(); v > b.holeMax {
		b.holeMax = v
	}
	if v := int64(st.OOOMax); v > b.oooMax {
		b.oooMax = v
	}
}

func (b *bondMetrics) rollLocked(now time.Time) {
	if now.Sub(b.maxAt) < 5*time.Minute {
		return
	}
	if now.Sub(b.maxAt) >= 10*time.Minute {
		b.holeMax, b.oooMax = 0, 0
	}
	b.holeOld, b.oooOld = b.holeMax, b.oooMax
	b.holeMax, b.oooMax = 0, 0
	b.maxAt = now
}

func (m *Metrics) writeBond(w io.Writer) {
	b := &m.bond
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rollLocked(time.Now())
	bonds.mu.Lock()
	open := len(bonds.m)
	bonds.mu.Unlock()
	max := func(a, c int64) int64 {
		if a > c {
			return a
		}
		return c
	}
	for _, s := range []struct {
		name, typ, help string
		val             int64
	}{
		{"kilvater_bonds_open", "gauge", "bonded flows open now", int64(open)},
		{"kilvater_bonds_total", "counter", "bonded flows ended", b.bonds},
		{"kilvater_bond_dup_bytes_total", "counter", "payload from clients that arrived twice (hedges, repeats)", int64(b.dup)},
		{"kilvater_bond_holes_total", "counter", "times a flow from a client waited for a chunk out of order", b.holes},
		{"kilvater_bond_hole_wait_ms_total", "counter", "time flows from clients spent waiting so", b.holeMs},
		{"kilvater_bond_hole_wait_max_ms", "gauge", "the longest such wait among the bonds ended in the last 5-10 minutes", max(b.holeMax, b.holeOld)},
		{"kilvater_bond_reorder_max_bytes", "gauge", "the most payload held out of order by one bond ended in the last 5-10 minutes", max(b.oooMax, b.oooOld)},
	} {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %d\n", s.name, s.help, s.name, s.typ, s.name, s.val)
	}
	names := make([]string, 0, len(b.routes))
	for n := range b.routes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, s := range []struct {
		name, typ, help string
		val             func(*bondRoute) int64
	}{
		{"kilvater_bond_legs_total", "counter", "bond legs accepted, by route", func(r *bondRoute) int64 { return r.legs }},
		{"kilvater_bond_legs_open", "gauge", "bond legs carrying now, by route", func(r *bondRoute) int64 { return r.open }},
		{"kilvater_bond_leg_sent_bytes_total", "counter", "SEQ payload given to ended legs towards clients, copies included", func(r *bondRoute) int64 { return int64(r.sent) }},
		{"kilvater_bond_leg_rcvd_bytes_total", "counter", "SEQ payload read off ended legs, copies included", func(r *bondRoute) int64 { return int64(r.rcvd) }},
		{"kilvater_bond_leg_stalls_total", "counter", "times a leg was rested as stalled", func(r *bondRoute) int64 { return r.rests }},
		{"kilvater_bond_leg_hedges_total", "counter", "copies of a held-up chunk sent on the leg", func(r *bondRoute) int64 { return r.hedges }},
		{"kilvater_bond_leg_retx_total", "counter", "chunks sent again on the leg after another lost them", func(r *bondRoute) int64 { return r.retx }},
		{"kilvater_bond_leg_seconds_total", "counter", "time ended legs ran", func(r *bondRoute) int64 { return r.durMs / 1000 }},
		{"kilvater_bond_leg_rtt_ms_sum", "counter", "smoothed chunk delay of ended legs, summed (divide by _count)", func(r *bondRoute) int64 { return r.rttMs }},
		{"kilvater_bond_leg_min_rtt_ms_sum", "counter", "least chunk delay of ended legs, summed", func(r *bondRoute) int64 { return r.minRttMs }},
		{"kilvater_bond_leg_rtt_count", "counter", "ended legs that measured a delay", func(r *bondRoute) int64 { return r.rtN }},
	} {
		if len(names) == 0 {
			break
		}
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", s.name, s.help, s.name, s.typ)
		for _, n := range names {
			fmt.Fprintf(w, "%s{route=%q} %d\n", s.name, n, s.val(b.routes[n]))
		}
	}
	if len(names) > 0 {
		fmt.Fprintf(w, "# HELP kilvater_bond_leg_ends_total why bond legs ended or were refused, by route\n# TYPE kilvater_bond_leg_ends_total counter\n")
		for _, n := range names {
			r := b.routes[n]
			ks := make([]string, 0, len(r.ends))
			for k := range r.ends {
				ks = append(ks, k)
			}
			sort.Strings(ks)
			for _, k := range ks {
				fmt.Fprintf(w, "kilvater_bond_leg_ends_total{route=%q,reason=%q} %d\n", n, k, r.ends[k])
			}
		}
	}
}
