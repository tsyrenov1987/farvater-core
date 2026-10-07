// Package switchboard is the local SOCKS5 front door. It owns the app sockets,
// asks the brain which path to use, drives wires, and turns what happened into
// receipts. It contains no transport code and no selection math.
package switchboard

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
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
	Ctx    string // network context the receipts are filed under at start; SetNetwork changes it
	Brain  brain.Config

	// MemoryFile, when set, keeps what the brain learned about each network
	// between sessions (DESIGN §9): read by New, written every
	// MemorySaveEvery, on a network change and by SaveMemory.
	MemoryFile      string
	MemorySaveEvery time.Duration

	// WhiteProbes are allow-listed sites a restricted mobile network still
	// lets through. When no path connects, they are dialled directly: an
	// answer means the network is up and shuts the paths out. Empty: never.
	WhiteProbes []string

	// Hosted names the kinds of path the app runs beside the core
	// (wire.IsHosted): they start asleep and wake when the app hands their
	// door to SetEndpoint. A path of a hosted kind not named here is skipped.
	Hosted []wire.Kind

	// Direct names the sites whose flows go straight to the network, around
	// every path (serveDirect): a name covers its subdomains, an IP address
	// only itself. In DirectNames form. Empty: none.
	Direct []string

	// User and Pass, when set, make SOCKS5 clients authenticate (RFC 1929).
	// The mobile apps set fresh random ones each session: every app on the
	// device can reach a loopback port, and an open proxy there would show it
	// the exit address.
	User, Pass string

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
		MemorySaveEvery:  2 * time.Minute,
		WhiteProbes:      []string{"ya.ru", "vk.com", "gosuslugi.ru"},
	}
}

// A restricted-network check runs at most this often and gives up after whiteProbeTimeout.
const (
	whiteProbeEveryMs = 60_000
	whiteProbeTimeout = 4 * time.Second
)

// carried counts the bytes one path has carried this session, both ways,
// flows still running and UDP included: the apps draw its live flow from how
// it grows.
type carried struct{ up, down atomic.Int64 }

// Switchboard serves SOCKS5 and keeps the brain fed.
type Switchboard struct {
	cfg     Config
	cat     *catalogue.Catalogue
	wires   map[string]wire.Wire
	infos   map[string]brain.PathInfo
	carried map[string]*carried
	order   []string
	Skipped []string

	mu       sync.Mutex
	b        *brain.Brain
	receipts []brain.Receipt
	savedAt  int64  // last periodic memory write
	saveSeq  uint64 // memory snapshots taken
	probing  bool   // a restricted-network check is out
	probedAt int64
	probe    func(ctx context.Context, hosts []string) bool
	udpBack  map[string]int64 // path → until when UDP tries it last (udp.go)
	wantTill map[string]int64 // hosted path → until when it is wanted up (Hosted)

	saveMu  sync.Mutex // one memory write at a time, never an older snapshot over a newer one
	written uint64

	started time.Time
	flows   atomic.Int64
	active  atomic.Int64
	retries atomic.Int64
	udp     atomic.Int64
	direct  atomic.Int64
}

// New builds wires for every supported path of the catalogue and a brain over them.
func New(cfg Config, cat *catalogue.Catalogue) (*Switchboard, error) {
	s := &Switchboard{cfg: cfg, cat: cat, wires: map[string]wire.Wire{}, infos: map[string]brain.PathInfo{}, carried: map[string]*carried{}, started: time.Now(), savedAt: nowMs(), probe: probeWhite, udpBack: map[string]int64{}, wantTill: map[string]int64{}}
	var infos []brain.PathInfo
	for _, e := range cat.Paths {
		if wire.IsHosted(e.Spec.Kind) && !slices.Contains(cfg.Hosted, e.Spec.Kind) {
			s.Skipped = append(s.Skipped, e.ID+": "+string(e.Spec.Kind)+" paths are not run by this app")
			continue
		}
		w, err := wire.Build(e.Spec)
		if err != nil {
			s.Skipped = append(s.Skipped, e.ID+": "+err.Error())
			continue
		}
		info := brain.PathInfo{ID: e.ID, SNI: e.Spec.ServerSNI(), IP: resolveIP(e.Spec.Host), Rail: e.Spec.Rail(), White: e.Labels.White, NotHTTP: !e.Spec.HTTPLike()}
		s.wires[e.ID] = w
		s.infos[e.ID] = info
		s.carried[e.ID] = &carried{}
		s.order = append(s.order, e.ID)
		infos = append(infos, info)
	}
	if len(infos) == 0 {
		return nil, errors.New("switchboard: no usable paths")
	}
	s.b = brain.New(cfg.Brain, cfg.Ctx, infos, uint64(time.Now().UnixNano()))
	for _, id := range s.order {
		if _, ok := s.wires[id].(wire.HostedWire); ok {
			s.b.Sleep(id, nowMs()) // until the app brings it up
		}
	}
	priors := map[string]map[string]brain.Prior{}
	for ctx, ps := range cat.Priors {
		priors[ctx] = map[string]brain.Prior{}
		for path, pr := range ps {
			priors[ctx][path] = brain.Prior{A: pr.A, B: pr.B}
		}
	}
	s.b.UseMemory(s.loadMemory(), priors, nowMs())
	return s, nil
}

// loadMemory reads Config.MemoryFile. A missing or unreadable file starts an
// empty memory; no file configured, none at all.
func (s *Switchboard) loadMemory() *brain.Memory {
	if s.cfg.MemoryFile == "" {
		return nil
	}
	m := brain.NewMemory()
	if data, err := os.ReadFile(s.cfg.MemoryFile); err == nil {
		if err := json.Unmarshal(data, m); err != nil || m.V != 1 {
			s.logf("memory: unreadable (%v), starting empty", err)
			m = brain.NewMemory()
		}
	}
	if m.Ctx == nil {
		m.Ctx = map[string]map[string]brain.PathMemory{}
	}
	m.Prune(nowMs())
	return m
}

// snapshot serialises the brain's memory for writing; called under s.mu.
func (s *Switchboard) snapshot(now int64) ([]byte, uint64) {
	m := s.b.Remember(now)
	if m == nil || s.cfg.MemoryFile == "" {
		return nil, 0
	}
	data, err := json.Marshal(m)
	if err != nil {
		return nil, 0
	}
	s.saveSeq++
	return data, s.saveSeq
}

func (s *Switchboard) writeMemory(data []byte, seq uint64) error {
	if data == nil {
		return nil
	}
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if seq <= s.written {
		return nil
	}
	tmp := s.cfg.MemoryFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.cfg.MemoryFile); err != nil {
		return err
	}
	s.written = seq
	return nil
}

// SaveMemory writes what the brain learned to Config.MemoryFile now; the apps
// call it when the tunnel stops. A no-op without a file.
func (s *Switchboard) SaveMemory() error {
	s.mu.Lock()
	data, seq := s.snapshot(nowMs())
	s.mu.Unlock()
	return s.writeMemory(data, seq)
}

// SetNetwork tells the switchboard the device moved to another network
// ("wifi:<gateway hash>", "cell", "wired"; DESIGN §9). The brain files new
// evidence under it and resumes what it knows of it, with no restart: live
// flows finish on their paths. The restricted variant of the same network is
// kept.
func (s *Switchboard) SetNetwork(ctx string) {
	s.mu.Lock()
	old := s.b.Ctx()
	if ctx == "" || strings.TrimSuffix(old, brain.RestrictedSuffix) == ctx {
		s.mu.Unlock()
		return
	}
	now := nowMs()
	s.b.SwitchContext(ctx, now)
	leader := s.b.Leader()
	data, seq := s.snapshot(now)
	s.mu.Unlock()
	s.logf("network %s → %s (leader %s)", old, ctx, leader)
	_ = s.writeMemory(data, seq)
}

// checkRestricted runs when no path connects: if an allow-listed site answers
// directly, the network is up and shuts the paths out, and the brain moves to
// (or stays in) the network's restricted variant. A result that arrives after
// the network changed is ignored.
func (s *Switchboard) checkRestricted(ctxAtStart string) {
	ctx, cancel := context.WithTimeout(context.Background(), whiteProbeTimeout)
	defer cancel()
	up := s.probe(ctx, s.cfg.WhiteProbes)
	s.mu.Lock()
	s.probing = false
	same := s.b.Ctx() == ctxAtStart
	if up && same {
		s.b.EnterRestricted(nowMs())
	}
	ctxNow := s.b.Ctx()
	s.mu.Unlock()
	s.logf("no path connects; allow-listed sites answer: %v; network %s", up && same, ctxNow)
}

// probeWhite reports whether any of hosts completes a verified TLS handshake
// on port 443, dialled directly rather than through a path.
func probeWhite(ctx context.Context, hosts []string) bool {
	res := make(chan bool, len(hosts))
	for _, h := range hosts {
		go func() {
			d := tls.Dialer{Config: &tls.Config{ServerName: h}}
			c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(h, "443"))
			if err == nil {
				c.Close()
			}
			res <- err == nil
		}()
	}
	for range hosts {
		if <-res {
			return true
		}
	}
	return false
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
	s.active.Add(1)
	defer s.active.Add(-1)
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	req, err := readSocks5(c, s.cfg.User, s.cfg.Pass)
	if err != nil {
		c.Close()
		return
	}
	if req.Cmd == socksFwdUDP {
		s.serveUDP(ctx, c)
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
	if s.isDirect(req.Host) {
		s.serveDirect(ctx, c, req)
		return
	}
	if err := replySocks5(c, 0); err != nil {
		c.Close()
		return
	}
	// Counted only once admitted: scanners, the iOS tunnel's liveness probe
	// and refused targets are no app's connection.
	s.flows.Add(1)
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

// pace waits for the governor's slot when dialling path means a handshake.
func (s *Switchboard) pace(ctx context.Context, path string) error {
	if !s.wires[path].NeedsHandshake() {
		return nil
	}
	if wait := s.acquire(path) - nowMs(); wait > 0 {
		select {
		case <-time.After(time.Duration(wait) * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (s *Switchboard) acquire(path string) int64 {
	info := s.infos[path]
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Gov.Acquire(info.SNI, info.IP, nowMs())
}

func (s *Switchboard) observe(r brain.Receipt) {
	s.mu.Lock()
	r.Ctx = s.b.Ctx()
	s.b.Observe(r)
	s.receipts = append(s.receipts, r)
	if n := s.cfg.ReceiptHistory; n > 0 && len(s.receipts) > n {
		s.receipts = s.receipts[len(s.receipts)-n:]
	}
	now := nowMs()
	check := ""
	if len(s.cfg.WhiteProbes) > 0 && !s.probing && now-s.probedAt >= whiteProbeEveryMs && s.b.NetDown(now) {
		s.probing, s.probedAt, check = true, now, s.b.Ctx()
	}
	var data []byte
	var seq uint64
	if every := s.cfg.MemorySaveEvery.Milliseconds(); every > 0 && now-s.savedAt >= every {
		s.savedAt = now
		data, seq = s.snapshot(now)
	}
	s.mu.Unlock()
	if check != "" {
		go s.checkRestricted(check)
	}
	_ = s.writeMemory(data, seq)
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
	Tripped        string  `json:"tripped,omitempty"`         // breaker signature while avoided as primary
	TrippedLeftMs  int64   `json:"tripped_left_ms,omitempty"` // until it is tried as a primary again
	Served         int     `json:"served"`                    // receipts served: first byte, no block signature
	Blocked        int     `json:"blocked"`                   // receipts with a block signature
	Asleep         bool    `json:"asleep,omitempty"`          // a hosted path whose transport is down
	UpBytes        int64   `json:"up_bytes"`                  // carried this session, running flows and UDP included
	DownBytes      int64   `json:"down_bytes"`
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
	Sig     string `json:"sig,omitempty"` // the breaker's block signature; empty when none
}

func view(r brain.Receipt) ReceiptView {
	return ReceiptView{r.AtMs, r.Path, r.End.String(), r.WireReadyMs, r.FirstByteMs, r.Up, r.Down, r.DurMs, r.MaxGapMs, r.Stalls, r.Dst, r.Explore, tripName(r.Sig())}
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
	UDP       int64         `json:"udp"`    // UDP associations that reached a path
	Direct    int64         `json:"direct"` // flows that went around the paths (Config.Direct)
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
		Listen: s.cfg.Listen, Ctx: s.b.Ctx(), Catalogue: s.cat.Title, Leader: s.b.Leader(),
		Flows: s.flows.Load(), Active: s.active.Load(), Retries: s.retries.Load(), UDP: s.udp.Load(), Direct: s.direct.Load(), Dropped: s.b.Dropped,
		Skipped: s.Skipped, Journal: len(s.b.J.Entries()),
	}
	for _, id := range s.order {
		ps := s.b.State(id)
		sp := s.wires[id].Spec()
		c := s.carried[id]
		server := fmt.Sprintf("%s:%d", sp.Host, sp.Port)
		if sp.Host == "" {
			server = sp.Provider // a hosted call has no address of its own
		}
		st.Paths = append(st.Paths, PathStatus{
			ID: id, Rail: sp.Rail(), Server: server, Leader: id == s.b.Leader(),
			DelivMean: ps.DelivMean(), FbMean: ps.FbMean(), Receipts: ps.Receipts,
			Recent15m: ps.RecentReceipts(now, 15*60*1000), P90FirstByteMs: ps.P90FirstByteMs(),
			Cut16: ps.Cut16, Parked: s.b.Diag.Parked(id, now), Tripped: tripName(s.b.Breaker.TrippedSig(id, now)),
			TrippedLeftMs: s.b.Breaker.TrippedLeftMs(id, now), Served: ps.Served, Blocked: ps.Blocked,
			Asleep: s.b.Asleep(id), UpBytes: c.up.Load(), DownBytes: c.down.Load(),
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
