// Package service is what stays running on Windows between the person's
// clicks: it holds the tunnel with the machine's rights, so the window asks
// for nothing and starts like any program. The window talks to it in lines of
// JSON (Handle); the connecting itself follows the phones' FarvaterVpnService:
// fetch the catalogue, start the switchboard, prove a delivery, and only then
// route the machine into the tunnel.
package service

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tsyrenov1987/farvater-core/brain"
	"github.com/tsyrenov1987/farvater-core/catalogue"
	"github.com/tsyrenov1987/farvater-core/desktop"
	"github.com/tsyrenov1987/farvater-core/switchboard"
	"github.com/tsyrenov1987/farvater-core/wire"
)

// Version is the build's own, set with -ldflags -X.
var Version = switchboard.Version

// What a failed connection tells the window (TunnelState.Reason).
const (
	reasonNoCatalogue = "NO_CATALOGUE"
	reasonCatalogue   = "CATALOGUE"
	reasonEstablish   = "ESTABLISH"
	reasonTunnel      = "TUNNEL"
)

const (
	proofTimeout = 15 * time.Second
	defaultProbe = "https://speed.cloudflare.com/__down?bytes=262144" // 256 KiB, what the phones prove with

	// Catalogue refresh, as CatalogueRefresh on the phones.
	refreshDefault = time.Hour
	refreshMin     = 30 * time.Minute
	refreshMax     = 12 * time.Hour
	refreshRetry   = 5 * time.Minute
	refreshSettle  = 10 * time.Second
	refreshNetGap  = 5 * time.Minute
)

// retryDelays is the pause after each failed proof.
var retryDelays = []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second, 20 * time.Second, 30 * time.Second}

// A replaced switchboard finishes its open flows for at most drainMax.
var (
	drainMax  = 10 * time.Minute
	drainTick = 5 * time.Second
)

// Proof is what a delivery test measured.
type Proof struct {
	OK          bool   `json:"ok"`
	Bytes       int64  `json:"bytes"`
	Ms          int64  `json:"ms"`
	FirstByteMs int64  `json:"first_byte_ms"`
	Path        string `json:"path,omitempty"`
	Rail        string `json:"rail,omitempty"`
	Error       string `json:"error,omitempty"`
}

// State is what the window shows.
type State struct {
	State     string `json:"state"` // off, loading, proving, on, failed
	Attempt   int    `json:"attempt,omitempty"`
	Error     string `json:"error,omitempty"`
	Proof     *Proof `json:"proof,omitempty"`
	SinceMs   int64  `json:"since_ms,omitempty"`
	FromSaved bool   `json:"from_saved,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// Prefs is what the service remembers, in the folder only the machine and
// administrators can read (it holds the access code).
type Prefs struct {
	Source    string              `json:"source,omitempty"`
	Text      string              `json:"text,omitempty"`
	Title     string              `json:"title,omitempty"`
	Paths     int                 `json:"paths,omitempty"`
	UpdatedMs int64               `json:"updatedMs,omitempty"`
	Provider  *catalogue.Provider `json:"provider,omitempty"`
	Autostart bool                `json:"autostart,omitempty"`
	// Wanted is a connection the person left on: a service restarted after a
	// crash brings it back, as the phones' sticky service does.
	Wanted bool `json:"wanted,omitempty"`
}

// System is the machine routed into the tunnel (*desktop.System).
type System interface {
	desktop.Packets
	Down()
}

// follower is a System that reports the machine moving to another network.
type follower interface {
	Follow(ctx context.Context, changed func(network string))
}

// Hooks are the parts that touch the machine and the network.
type Hooks struct {
	Fetch func(url string) ([]byte, *catalogue.Provider, error)
	Up    func(nodes []netip.Addr, logf func(string, ...any)) (System, error)
	Serve func(ctx context.Context, sys System, serve desktop.Conns, user, pass string, logf func(string, ...any)) error
	// Prove is nil for the real delivery test.
	Prove func(ctx context.Context, sb *switchboard.Switchboard, user, pass, probeURL string) Proof
	Sleep func(ctx context.Context, d time.Duration) bool
	// After, when set, replaces the timer between catalogue refreshes.
	After func(d time.Duration) <-chan time.Time
}

// RealHooks routes the actual machine.
func RealHooks() Hooks {
	return Hooks{
		Fetch: catalogue.FetchWithProvider,
		Up: func(nodes []netip.Addr, logf func(string, ...any)) (System, error) {
			s, err := desktop.Up(desktop.Options{Nodes: nodes, Logf: logf})
			if err != nil {
				return nil, err
			}
			return s, nil
		},
		Serve: func(ctx context.Context, sys System, serve desktop.Conns, user, pass string, logf func(string, ...any)) error {
			_, err := desktop.Start(ctx, sys, serve, user, pass, logf)
			return err
		},
	}
}

// fetched is a catalogue that loaded and parsed.
type fetched struct {
	source   string
	text     string
	cat      *catalogue.Catalogue
	paths    int
	provider *catalogue.Provider
}

// Session is the one connection of this machine.
type Session struct {
	hooks Hooks
	dir   string
	logf  func(string, ...any)

	mu       sync.Mutex
	state    State
	prefs    Prefs
	imported *fetched // what the last import brought; save takes only this
	cancel   context.CancelFunc
	done     chan struct{}
	live     *live
	closed   bool

	proofRead, proofSize atomic.Int64
	netKick              chan struct{}
}

// New reads what was saved in dir.
func New(dir string, hooks Hooks, logf func(string, ...any)) *Session {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if hooks.Sleep == nil {
		hooks.Sleep = sleep
	}
	if hooks.After == nil {
		hooks.After = time.After
	}
	s := &Session{hooks: hooks, dir: dir, logf: logf, state: State{State: "off"}, netKick: make(chan struct{}, 1)}
	if b, err := os.ReadFile(s.prefsFile()); err == nil {
		if err := json.Unmarshal(b, &s.prefs); err != nil {
			logf("prefs: %v", err)
		}
	}
	return s
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (s *Session) prefsFile() string { return filepath.Join(s.dir, "prefs.json") }

// writePrefs is called with mu held.
func (s *Session) writePrefs() {
	b, _ := json.Marshal(s.prefs)
	_ = os.MkdirAll(s.dir, 0o700)
	tmp := s.prefsFile() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		err = os.Rename(tmp, s.prefsFile())
		if err != nil {
			s.logf("prefs: %v", err)
		}
	} else {
		s.logf("prefs: %v", err)
	}
}

// Resume connects when the service starts, if the person asked for that or
// left a connection on before a crash.
func (s *Session) Resume() {
	s.mu.Lock()
	p := s.prefs
	s.mu.Unlock()
	if p.Source != "" && (p.Autostart || p.Wanted) {
		s.Connect()
	}
}

// Connect starts a connection, replacing the one there is.
func (s *Session) Connect() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	prev := s.done
	if s.cancel != nil {
		s.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.cancel, s.done = cancel, done
	s.state = State{State: "loading"}
	s.prefs.Wanted = true
	s.writePrefs()
	go func() {
		defer close(done)
		defer cancel()
		if prev != nil {
			<-prev
		}
		if ctx.Err() == nil {
			s.run(ctx)
		}
	}()
}

// Disconnect ends the connection; the window sees it off at once, the
// machine is put back in the background.
func (s *Session) Disconnect() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	s.state = State{State: "off"}
	s.prefs.Wanted = false
	s.writePrefs()
}

// Close ends everything and waits. machineOff is the computer shutting down:
// the next boot connects only if the person asked for that.
func (s *Session) Close(machineOff bool) {
	s.mu.Lock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	if machineOff && s.prefs.Wanted {
		s.prefs.Wanted = false
		s.writePrefs()
	}
	done := s.done
	s.mu.Unlock()
	if done != nil {
		<-done
	}
}

// publish shows a state, unless this run has been told to stop: whoever
// stopped it has set the state already.
func (s *Session) publish(ctx context.Context, st State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() == nil {
		s.state = st
	}
}

func (s *Session) fail(ctx context.Context, reason, detail string) {
	s.logf("failed: %s %s", reason, detail)
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return
	}
	s.state = State{State: "failed", Reason: reason, Detail: detail}
	s.prefs.Wanted = false
	s.writePrefs()
}

// CurrentState is what the window polls.
func (s *Session) CurrentState() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func explained(err error) string {
	if e := desktop.Explain(err); e != nil {
		return e.Error()
	}
	return err.Error()
}

func runnable(c *catalogue.Catalogue) int {
	n := 0
	for _, e := range c.Paths {
		if !wire.IsHosted(e.Spec.Kind) {
			n++
		}
	}
	return n
}

func (s *Session) fetchOne(url string) (*fetched, error) {
	body, prov, err := s.hooks.Fetch(url)
	if err != nil {
		return nil, err
	}
	cat, err := catalogue.Parse(body)
	if err != nil {
		return nil, err
	}
	return &fetched{source: url, text: string(body), cat: cat, paths: runnable(cat), provider: prov}, nil
}

// fetch tries the source's mirrors; a person's disconnect does not wait for
// a mirror's timeout.
func (s *Session) fetch(ctx context.Context, source string) (*fetched, error) {
	type result struct {
		f   *fetched
		err error
	}
	ch := make(chan result, 1)
	go func() {
		var r result
		for _, u := range mirrors(source) {
			if ctx.Err() != nil {
				break
			}
			r.f, r.err = s.fetchOne(u)
			if r.err == nil || settled(r.err) {
				break
			}
		}
		ch <- r
	}()
	select {
	case r := <-ch:
		return r.f, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Session) remember(f *fetched) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prefs.Text, s.prefs.Paths, s.prefs.Provider = f.text, f.paths, f.provider
	s.prefs.UpdatedMs = time.Now().UnixMilli()
	s.writePrefs()
}

func (s *Session) config(cat *catalogue.Catalogue, user, pass, network string) switchboard.Config {
	cfg := switchboard.DefaultConfig()
	cfg.User, cfg.Pass = user, pass
	if network != "" {
		cfg.Ctx = network
	}
	cfg.RuDirect, cfg.DirectName = true, desktop.DirectName
	cfg.RuDialTimeout, cfg.RuRetryAfter = desktop.RuDialTimeout, desktop.RuRetryAfter
	cfg.ProbeURL = defaultProbe
	if len(cat.ProbeURLs) > 0 {
		cfg.ProbeURL = cat.ProbeURLs[0]
	}
	cfg.MemoryFile = filepath.Join(s.dir, "memory.json")
	return cfg
}

// live is the running switchboard; a fresh catalogue replaces it under the
// open tunnel.
type live struct {
	user, pass string

	mu     sync.Mutex
	sb     *switchboard.Switchboard
	cat    *catalogue.Catalogue
	life   context.Context
	cancel context.CancelFunc
}

func (l *live) current() *switchboard.Switchboard {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sb
}

func (s *Session) setLive(l *live) {
	s.mu.Lock()
	s.live = l
	s.mu.Unlock()
}

func (s *Session) run(ctx context.Context) {
	s.mu.Lock()
	p := s.prefs
	s.mu.Unlock()
	if p.Source == "" {
		s.fail(ctx, reasonNoCatalogue, "")
		return
	}

	f, err := s.fetch(ctx, p.Source)
	if ctx.Err() != nil {
		return
	}
	fromSaved := false
	var cat *catalogue.Catalogue
	provider := p.Provider
	switch {
	case err == nil:
		s.remember(f)
		cat, provider = f.cat, f.provider
	case p.Text != "":
		s.logf("catalogue: %v; using the saved copy", err)
		fromSaved = true
		if cat, err = catalogue.Parse([]byte(p.Text)); err != nil {
			s.fail(ctx, reasonCatalogue, err.Error())
			return
		}
	default:
		s.fail(ctx, reasonCatalogue, explained(err))
		return
	}

	l := &live{user: rand.Text(), pass: rand.Text(), cat: cat}
	sb, err := switchboard.New(s.config(cat, l.user, l.pass, ""), cat)
	if err != nil {
		s.fail(ctx, reasonCatalogue, err.Error())
		return
	}
	l.sb = sb
	l.life, l.cancel = context.WithCancel(ctx)
	defer l.cancel()
	sb.Attach(l.life)
	s.setLive(l)
	defer func() {
		_ = l.current().SaveMemory()
		s.setLive(nil)
	}()
	s.logf("%d paths, saved copy: %v", len(sb.Paths()), fromSaved)

	// Nothing of the machine has changed yet: without a network this just
	// waits, and the person's internet stays as it was.
	probe := defaultProbe
	if len(cat.ProbeURLs) > 0 {
		probe = cat.ProbeURLs[0]
	}
	prove := s.hooks.Prove
	if prove == nil {
		prove = s.prove
	}
	var proof Proof
	for attempt, last := 1, ""; ; attempt++ {
		s.publish(ctx, State{State: "proving", Attempt: attempt, Error: last})
		proof = prove(ctx, sb, l.user, l.pass, probe)
		if ctx.Err() != nil {
			return
		}
		if proof.OK {
			break
		}
		last = proof.Error
		s.logf("proof %d: %s", attempt, last)
		if !s.hooks.Sleep(ctx, retryDelays[min(attempt, len(retryDelays))-1]) {
			return
		}
	}

	sys, err := s.hooks.Up(desktop.NodeAddrs(cat), s.logf)
	if err != nil {
		s.fail(ctx, reasonEstablish, err.Error())
		return
	}
	defer sys.Down()
	serve := func(ctx context.Context, c net.Conn) { l.current().ServeConn(ctx, c) }
	if err := s.hooks.Serve(ctx, sys, serve, l.user, l.pass, s.logf); err != nil {
		s.fail(ctx, reasonTunnel, err.Error())
		return
	}
	on := State{State: "on", Proof: &proof, SinceMs: time.Now().UnixMilli(), FromSaved: fromSaved}
	s.publish(ctx, on)
	s.logf("on: %s %s, %d ms to the first byte", proof.Path, proof.Rail, proof.FirstByteMs)
	if fw, ok := sys.(follower); ok {
		go fw.Follow(ctx, func(network string) {
			s.logf("network changed: %s", network)
			l.current().SetNetwork(network)
			select {
			case s.netKick <- struct{}{}:
			default:
			}
		})
	}
	first := everyMs(provider)
	if fromSaved {
		first = refreshRetry
	}
	s.refresh(ctx, l, p.Source, first)
}

func everyMs(p *catalogue.Provider) time.Duration {
	if p == nil || p.UpdateHours <= 0 {
		return refreshDefault
	}
	return min(max(time.Duration(p.UpdateHours)*time.Hour, refreshMin), refreshMax)
}

// refresh keeps the catalogue current under the open tunnel until ctx ends.
func (s *Session) refresh(ctx context.Context, l *live, source string, first time.Duration) {
	nextAt, triedAt := time.Now().Add(first), time.Now()
	for {
		kicked := false
		select {
		case <-ctx.Done():
			return
		case <-s.hooks.After(max(time.Until(nextAt), time.Second)):
		case <-s.netKick:
			kicked = true
		}
		if kicked {
			if time.Since(triedAt) < refreshNetGap {
				continue
			}
			if !s.hooks.Sleep(ctx, refreshSettle) {
				return
			}
		}
		triedAt = time.Now()
		f, err := s.fetch(ctx, source)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			s.logf("catalogue refresh: %v", err)
			nextAt = time.Now().Add(refreshRetry)
			continue
		}
		s.remember(f)
		s.savedCopyGone(ctx)
		changed, err := s.reload(ctx, l, f.cat)
		s.logf("catalogue refresh: changed=%v paths=%d err=%v", changed, f.paths, err)
		nextAt = time.Now().Add(everyMs(f.provider))
		if err != nil && strings.HasPrefix(err.Error(), "restricted") {
			nextAt = time.Now().Add(refreshRetry)
		}
	}
}

// savedCopyGone takes the "using the saved copy" note off once a fresh
// catalogue has come.
func (s *Session) savedCopyGone(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() == nil && s.state.State == "on" {
		s.state.FromSaved = false
	}
}

// reload gives the open tunnel a fresh catalogue (mobile.Reload on the
// phones): same paths change nothing; otherwise a new switchboard takes over
// with what the session has learned, and the flows open on the old one
// finish there.
func (s *Session) reload(ctx context.Context, l *live, cat *catalogue.Catalogue) (bool, error) {
	l.mu.Lock()
	old, had := l.sb, l.cat
	l.mu.Unlock()
	if samePaths(had, cat) {
		return false, nil
	}
	restricted := old.Restricted()
	_ = old.SaveMemory()
	next, err := switchboard.New(s.config(cat, l.user, l.pass, strings.TrimSuffix(old.Ctx(), brain.RestrictedSuffix)), cat)
	if err != nil {
		return false, err
	}
	if restricted { // the new one starts where the old one stood
		next.EnterRestricted()
	}
	if ctx.Err() != nil {
		next.Discard()
		return false, ctx.Err()
	}
	next.Inherit(old)
	life, cancel := context.WithCancel(ctx)
	next.Attach(life)
	l.mu.Lock()
	oldLife, oldCancel := l.life, l.cancel
	l.sb, l.cat, l.life, l.cancel = next, cat, life, cancel
	l.mu.Unlock()
	if n := strings.TrimSuffix(old.Ctx(), brain.RestrictedSuffix); n != "" {
		next.SetNetwork(n) // the machine moved while the new one was built
	}
	go drain(old, oldLife, oldCancel)
	return true, nil
}

func drain(old *switchboard.Switchboard, ctx context.Context, c context.CancelFunc) {
	t := time.NewTicker(drainTick)
	defer t.Stop()
	until := time.Now().Add(drainMax)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if old.Active() == 0 || time.Now().After(until) {
			c()
			return
		}
	}
}

func samePaths(a, b *catalogue.Catalogue) bool {
	if a == nil || b == nil {
		return false
	}
	return slices.Equal(pathKeys(a), pathKeys(b))
}

func pathKeys(c *catalogue.Catalogue) []string {
	out := make([]string, 0, len(c.Paths))
	for _, e := range c.Paths {
		l, _ := json.Marshal(e.Labels)
		out = append(out, e.ID+"\x00"+e.URI+"\x00"+string(l))
	}
	slices.Sort(out)
	return out
}
