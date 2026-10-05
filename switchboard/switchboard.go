// Package switchboard is the local SOCKS5 front door. It owns the app sockets,
// asks the brain which path to use, drives wires, and turns what happened into
// receipts. It contains no transport code and no selection math.
package switchboard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tsyrenov1987/farvater-core/brain"
	"github.com/tsyrenov1987/farvater-core/catalogue"
	"github.com/tsyrenov1987/farvater-core/wire"
)

// Version of the core; the CLI prints it and the admin API reports it.
const Version = "0.1.0-dev"

// Config of a switchboard.
type Config struct {
	Listen string
	Ctx    string // network context name the receipts are filed under
	Brain  brain.Config

	DialTimeout      time.Duration
	FirstByteTimeout time.Duration
	FirstPayloadWait time.Duration
	StallMs          int64
	PreludeCap       int
	ReceiptHistory   int

	Log func(format string, args ...any)
}

// DefaultConfig returns the defaults the CLI uses.
func DefaultConfig() Config {
	return Config{
		Listen:           "127.0.0.1:1080",
		Ctx:              "default",
		Brain:            brain.DefaultConfig(),
		DialTimeout:      8 * time.Second,
		FirstByteTimeout: 6 * time.Second,
		FirstPayloadWait: 500 * time.Millisecond,
		StallMs:          4000,
		PreludeCap:       64 * 1024,
		ReceiptHistory:   200,
	}
}

// Switchboard serves SOCKS5 and keeps the brain fed.
type Switchboard struct {
	cfg     Config
	cat     *catalogue.Catalogue
	wires   map[string]wire.Wire
	infos   map[string]brain.PathInfo
	order   []string
	Skipped []string

	mu       sync.Mutex
	b        *brain.Brain
	receipts []brain.Receipt

	started time.Time
	flows   atomic.Int64
	active  atomic.Int64
	retries atomic.Int64
}

// New builds wires for every supported path of the catalogue and a brain over them.
func New(cfg Config, cat *catalogue.Catalogue) (*Switchboard, error) {
	s := &Switchboard{cfg: cfg, cat: cat, wires: map[string]wire.Wire{}, infos: map[string]brain.PathInfo{}, started: time.Now()}
	var infos []brain.PathInfo
	for _, e := range cat.Paths {
		w, err := wire.Build(e.Spec)
		if err != nil {
			s.Skipped = append(s.Skipped, e.ID+": "+err.Error())
			continue
		}
		info := brain.PathInfo{ID: e.ID, SNI: e.Spec.ServerSNI(), IP: resolveIP(e.Spec.Host), Rail: e.Spec.Rail()}
		s.wires[e.ID] = w
		s.infos[e.ID] = info
		s.order = append(s.order, e.ID)
		infos = append(infos, info)
	}
	if len(infos) == 0 {
		return nil, errors.New("switchboard: no usable paths")
	}
	s.b = brain.New(cfg.Brain, cfg.Ctx, infos, uint64(time.Now().UnixNano()))
	for path, pr := range cat.Priors[cfg.Ctx] {
		if _, ok := s.wires[path]; ok {
			s.b.SetPrior(path, pr.A, pr.B, 1)
		}
	}
	return s, nil
}

func resolveIP(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return host
	}
	return addrs[0].IP.String()
}

// Paths lists the usable path ids in catalogue order.
func (s *Switchboard) Paths() []string { return append([]string(nil), s.order...) }

// Serve accepts SOCKS5 connections until ctx ends.
func (s *Switchboard) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	return s.serveListener(ctx, ln)
}

// Start listens synchronously (so the caller knows the port is up) and serves
// in the background until ctx ends. Used by the mobile apps.
func (s *Switchboard) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	go func() { _ = s.serveListener(ctx, ln) }()
	return nil
}

func (s *Switchboard) serveListener(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
		for _, w := range s.wires {
			w.Close()
		}
	}()
	s.logf("listening on %s (%d paths, ctx=%s)", s.cfg.Listen, len(s.order), s.cfg.Ctx)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go s.handle(ctx, c)
	}
}

// nonGlobal are ranges that Go's netip does not flag but that mean nothing
// at a path's exit.
var nonGlobal = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // shared address space (CGNAT)
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking; the apps' tunnel and DNS addresses
}

// routable reports whether a destination can mean anything at a path's exit:
// any name, or a global unicast address outside private and shared ranges.
func routable(host string) bool {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return true
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, p := range nonGlobal {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

func classify(port int) brain.DstClass {
	switch port {
	case 443:
		return brain.DstTLS443
	case 53:
		return brain.DstDNS
	}
	return brain.DstOther
}

func (s *Switchboard) handle(ctx context.Context, c net.Conn) {
	s.flows.Add(1)
	s.active.Add(1)
	defer s.active.Add(-1)
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	req, err := readSocks5(c)
	if err != nil {
		c.Close()
		return
	}
	if !routable(req.Host) {
		// Refused at once, with no dial and no receipt: such a flow would only
		// file failures against healthy paths. The usual case is Android probing
		// DNS-over-TLS on the tunnel's own DNS address.
		_ = replySocks5(c, 2) // connection not allowed by ruleset
		c.Close()
		return
	}
	if err := replySocks5(c, 0); err != nil {
		c.Close()
		return
	}
	f := &flow{
		s: s, client: c,
		target: wire.Target{Host: req.Host, Port: req.Port},
		class:  classify(req.Port),
		up:     make(chan []byte, 8),
		done:   make(chan struct{}),
	}
	// First payload: most apps send it right after the SOCKS reply. Carrying it
	// together with the proxy request saves a round trip.
	_ = c.SetReadDeadline(time.Now().Add(s.cfg.FirstPayloadWait))
	buf := make([]byte, 16*1024)
	n, rerr := c.Read(buf)
	_ = c.SetDeadline(time.Time{})
	if n > 0 {
		f.prelude = append([]byte(nil), buf[:n]...)
	}
	if rerr != nil {
		var ne net.Error
		if !errors.As(rerr, &ne) || !ne.Timeout() {
			c.Close()
			return
		}
	}
	go f.readLoop()
	f.serve(ctx)
}

func (s *Switchboard) pick(now int64, dst string, class brain.DstClass) brain.Decision {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Pick(now, dst, class)
}

func (s *Switchboard) acquire(path string) int64 {
	info := s.infos[path]
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Gov.Acquire(info.SNI, info.IP, nowMs())
}

func (s *Switchboard) observe(r brain.Receipt) {
	s.mu.Lock()
	s.b.Observe(r)
	s.receipts = append(s.receipts, r)
	if n := s.cfg.ReceiptHistory; n > 0 && len(s.receipts) > n {
		s.receipts = s.receipts[len(s.receipts)-n:]
	}
	s.mu.Unlock()
	s.logf("receipt %s %s wire=%dms fb=%dms down=%d up=%d dur=%dms stalls=%d dst=%s", r.Path, r.End, r.WireReadyMs, r.FirstByteMs, r.Down, r.Up, r.DurMs, r.Stalls, r.Dst)
}

func (s *Switchboard) logf(format string, args ...any) {
	if s.cfg.Log != nil {
		s.cfg.Log(format, args...)
	}
}

// PathStatus is one row of Status.
type PathStatus struct {
	ID             string  `json:"id"`
	Rail           string  `json:"rail"`
	Server         string  `json:"server"`
	Leader         bool    `json:"leader"`
	DelivMean      float64 `json:"deliv_mean"`
	FbMean         float64 `json:"fb_mean"`
	Receipts       int     `json:"receipts"`
	Recent15m      int     `json:"recent_15m"`
	P90FirstByteMs int64   `json:"p90_first_byte_ms"`
	Cut16          bool    `json:"cut16"`
	Parked         bool    `json:"parked"`
	Tripped        string  `json:"tripped,omitempty"` // breaker signature while avoided as primary
}

func tripName(sig brain.BlockSig) string {
	if sig == brain.SigNone {
		return ""
	}
	return sig.String()
}

// ReceiptView is the JSON form of a receipt.
type ReceiptView struct {
	At      int64  `json:"at_ms"`
	Path    string `json:"path"`
	End     string `json:"end"`
	WireMs  int64  `json:"wire_ms"`
	FbMs    int64  `json:"first_byte_ms"`
	Up      int64  `json:"up"`
	Down    int64  `json:"down"`
	DurMs   int64  `json:"dur_ms"`
	GapMs   int64  `json:"max_gap_ms"`
	Stalls  int    `json:"stalls"`
	Dst     string `json:"dst"`
	Explore bool   `json:"explore"`
}

func view(r brain.Receipt) ReceiptView {
	return ReceiptView{r.AtMs, r.Path, r.End.String(), r.WireReadyMs, r.FirstByteMs, r.Up, r.Down, r.DurMs, r.MaxGapMs, r.Stalls, r.Dst, r.Explore}
}

// Status is the admin snapshot.
type Status struct {
	Version   string        `json:"version"`
	UptimeSec int64         `json:"uptime_sec"`
	Listen    string        `json:"listen"`
	Ctx       string        `json:"ctx"`
	Catalogue string        `json:"catalogue"`
	Leader    string        `json:"leader"`
	Flows     int64         `json:"flows"`
	Active    int64         `json:"active"`
	Retries   int64         `json:"retries"`
	Dropped   int           `json:"dropped"`
	Paths     []PathStatus  `json:"paths"`
	Skipped   []string      `json:"skipped"`
	Journal   int           `json:"journal_entries"`
	Recent    []ReceiptView `json:"recent_receipts"`
}

// Status returns the current snapshot.
func (s *Switchboard) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := nowMs()
	st := Status{
		Version: Version, UptimeSec: int64(time.Since(s.started).Seconds()),
		Listen: s.cfg.Listen, Ctx: s.cfg.Ctx, Catalogue: s.cat.Title, Leader: s.b.Leader(),
		Flows: s.flows.Load(), Active: s.active.Load(), Retries: s.retries.Load(), Dropped: s.b.Dropped,
		Skipped: s.Skipped, Journal: len(s.b.J.Entries()),
	}
	for _, id := range s.order {
		ps := s.b.State(id)
		sp := s.wires[id].Spec()
		st.Paths = append(st.Paths, PathStatus{
			ID: id, Rail: sp.Rail(), Server: fmt.Sprintf("%s:%d", sp.Host, sp.Port), Leader: id == s.b.Leader(),
			DelivMean: ps.DelivMean(), FbMean: ps.FbMean(), Receipts: ps.Receipts,
			Recent15m: ps.RecentReceipts(now, 15*60*1000), P90FirstByteMs: ps.P90FirstByteMs(),
			Cut16: ps.Cut16, Parked: s.b.Diag.Parked(id, now), Tripped: tripName(s.b.Breaker.TrippedSig(id, now)),
		})
	}
	n := len(s.receipts)
	if n > 50 {
		n = 50
	}
	for _, r := range s.receipts[len(s.receipts)-n:] {
		st.Recent = append(st.Recent, view(r))
	}
	return st
}

// Journal returns the brain's decision journal.
func (s *Switchboard) Journal() []brain.Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.J.Entries()
}

// Receipts returns the receipt history (oldest first).
func (s *Switchboard) Receipts() []ReceiptView {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ReceiptView, 0, len(s.receipts))
	for _, r := range s.receipts {
		out = append(out, view(r))
	}
	return out
}
