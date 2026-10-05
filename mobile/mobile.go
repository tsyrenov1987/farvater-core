// Package mobile is the gomobile-bindable surface of farvater-core used by the
// Android and iOS apps. Everything crosses the language boundary as strings,
// ints, bools and JSON; the app never sees Go types.
//
// The app owns the tunnel device and the socket-protection policy; this
// package only runs the switchboard on a loopback SOCKS5 port, closed by
// per-session credentials, and reports what it measured.
package mobile

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tsyrenov1987/farvater-core/catalogue"
	"github.com/tsyrenov1987/farvater-core/switchboard"
)

// DefaultProbeURL is fetched by ProveDelivery when neither the caller nor the
// catalogue names a probe. 256 KiB: enough to cross a 16 KiB cut.
const DefaultProbeURL = "https://speed.cloudflare.com/__down?bytes=262144"

var (
	mu         sync.Mutex
	sb         *switchboard.Switchboard
	cancel     context.CancelFunc
	listen     string
	user, pass string
	probe      string
)

// Version is the core version string.
func Version() string { return switchboard.Version }

// SetMemoryLimit caps the Go runtime's memory at bytes (a soft limit: the
// collector runs harder as it nears the cap). An iOS packet tunnel gets about
// 50 MiB for the whole process and is killed past it, so the iOS app sets this
// before Start. Zero or less leaves the limit as it is.
func SetMemoryLimit(bytes int64) {
	if bytes > 0 {
		debug.SetMemoryLimit(bytes)
	}
}

// MemoryJSON reports the Go runtime's share of the process, so the iOS tunnel
// can tell the core's memory from the rest of its budget:
// {"total": bytes the runtime holds from the OS, "heap": live heap objects,
// "stacks": goroutine stacks, "goroutines": n}.
func MemoryJSON() string {
	s := []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/memory/classes/heap/stacks:bytes"},
		{Name: "/sched/goroutines:goroutines"},
	}
	metrics.Read(s)
	return toJSON(map[string]uint64{
		"total":      s[0].Value.Uint64() - s[1].Value.Uint64(),
		"heap":       s[2].Value.Uint64(),
		"stacks":     s[3].Value.Uint64(),
		"goroutines": s[4].Value.Uint64(),
	})
}

// Start loads the catalogue and starts the switchboard on 127.0.0.1:socksPort.
// catalogueSrc is either an http(s) URL of a catalogue/subscription, or the
// catalogue text itself (JSON, base64 subscription, or share links).
// networkCtx names the network the receipts are filed under (e.g. "wifi").
// It returns once the SOCKS5 port is listening; the port accepts only the
// credentials SocksUser and SocksPass report, fresh for each Start.
func Start(catalogueSrc string, socksPort int, networkCtx string) error {
	mu.Lock()
	defer mu.Unlock()
	if sb != nil {
		return errors.New("already running")
	}
	cat, err := loadCatalogue(catalogueSrc)
	if err != nil {
		return err
	}
	cfg := switchboard.DefaultConfig()
	listen = net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))
	cfg.Listen = listen
	cfg.User, cfg.Pass = rand.Text(), rand.Text()
	if networkCtx != "" {
		cfg.Ctx = networkCtx
	}
	s, err := switchboard.New(cfg, cat)
	if err != nil {
		return err
	}
	ctx, c := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		c()
		return err
	}
	sb, cancel = s, c
	user, pass = cfg.User, cfg.Pass
	probe = DefaultProbeURL
	if len(cat.ProbeURLs) > 0 {
		probe = cat.ProbeURLs[0]
	}
	return nil
}

func loadCatalogue(src string) (*catalogue.Catalogue, error) {
	src = strings.TrimSpace(src)
	if src == "" {
		return nil, errors.New("empty catalogue")
	}
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		return catalogue.Load(src)
	}
	return catalogue.Parse([]byte(src))
}

// Stop shuts the switchboard down. It is safe to call when not running.
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if cancel != nil {
		cancel()
	}
	sb, cancel = nil, nil
}

// SocksUser and SocksPass are the credentials of the running switchboard's
// SOCKS5 port; the tunnel presents them (RFC 1929). Other apps on the device
// can reach a loopback port but not these.
func SocksUser() string {
	mu.Lock()
	defer mu.Unlock()
	return user
}

// SocksPass: see SocksUser.
func SocksPass() string {
	mu.Lock()
	defer mu.Unlock()
	return pass
}

// Running reports whether the switchboard is up.
func Running() bool {
	mu.Lock()
	defer mu.Unlock()
	return sb != nil
}

func current() *switchboard.Switchboard {
	mu.Lock()
	defer mu.Unlock()
	return sb
}

func toJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// StatusJSON returns the switchboard status (paths, leader, breaker state).
func StatusJSON() string {
	s := current()
	if s == nil {
		return "{}"
	}
	return toJSON(s.Status())
}

// ReceiptsJSON returns the receipt history, oldest first.
func ReceiptsJSON() string {
	s := current()
	if s == nil {
		return "[]"
	}
	return toJSON(s.Receipts())
}

// JournalJSON returns the brain's decision journal.
func JournalJSON() string {
	s := current()
	if s == nil {
		return "[]"
	}
	return toJSON(s.Journal())
}

// FetchCatalogue downloads a catalogue URL and returns JSON
// {"ok":true,"text":"...","paths":n,"title":"..."} or {"ok":false,"error":"..."}.
// The app stores text as the last good copy and starts from it when the URL
// is unreachable.
func FetchCatalogue(catalogueURL string) string {
	body, err := catalogue.Fetch(strings.TrimSpace(catalogueURL))
	if err != nil {
		return toJSON(map[string]any{"ok": false, "error": err.Error()})
	}
	cat, err := catalogue.Parse(body)
	if err != nil {
		return toJSON(map[string]any{"ok": false, "error": err.Error()})
	}
	return toJSON(map[string]any{"ok": true, "text": string(body), "paths": len(cat.Paths), "title": cat.Title})
}

// ValidateCatalogue parses a catalogue without starting anything and returns
// JSON {"ok":true,"paths":n,"title":"..."} or {"ok":false,"error":"..."} for
// the import screen.
func ValidateCatalogue(catalogueSrc string) string {
	cat, err := loadCatalogue(catalogueSrc)
	if err != nil {
		return toJSON(map[string]any{"ok": false, "error": err.Error()})
	}
	return toJSON(map[string]any{"ok": true, "paths": len(cat.Paths), "title": cat.Title})
}

// The probe in flight, for the apps' live counter: bytes read so far and the
// length the server announced (-1 when it sent none).
var probeRead, probeSize atomic.Int64

// ProofProgress returns JSON {"bytes":n,"total":m} for the latest
// ProveDelivery: while it runs, how much of the probe has arrived.
func ProofProgress() string {
	return toJSON(map[string]int64{"bytes": probeRead.Load(), "total": probeSize.Load()})
}

// countingDiscard drops the probe body, counting it into probeRead.
type countingDiscard struct{}

func (countingDiscard) Write(p []byte) (int, error) {
	probeRead.Add(int64(len(p)))
	return len(p), nil
}

// proof is the result of ProveDelivery.
type proof struct {
	OK          bool   `json:"ok"`
	Bytes       int64  `json:"bytes"`
	Ms          int64  `json:"ms"`
	FirstByteMs int64  `json:"first_byte_ms"`
	Path        string `json:"path,omitempty"`
	Rail        string `json:"rail,omitempty"`
	Error       string `json:"error,omitempty"`
}

// ProveDelivery fetches probeURL (https; empty means the catalogue's probe, or
// DefaultProbeURL) through the running switchboard — the same SOCKS5 door
// every app uses — and returns JSON describing what was actually delivered:
// bytes, total and first-byte time, and the path that carried it. The app
// shows "connected" only after this succeeds.
func ProveDelivery(probeURL string, timeoutMs int) string {
	s := current()
	mu.Lock()
	addr, su, sp := listen, user, pass
	if probeURL == "" {
		probeURL = probe
	}
	mu.Unlock()
	if s == nil {
		return toJSON(proof{Error: "not running"})
	}
	probeRead.Store(0)
	probeSize.Store(0)
	u, err := url.Parse(probeURL)
	if err != nil || u.Scheme != "https" {
		return toJSON(proof{Error: "probe url must be https"})
	}
	ctx, c := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer c()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, hostport string) (net.Conn, error) {
			return socksConnect(ctx, addr, su, sp, hostport)
		},
		TLSClientConfig:   &tls.Config{ServerName: u.Hostname()},
		DisableKeepAlives: true,
	}
	start := time.Now()
	var first time.Duration
	trace := &httptrace.ClientTrace{GotFirstResponseByte: func() { first = time.Since(start) }}
	req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), "GET", probeURL, nil)
	req.Header.Set("User-Agent", "farvater-probe/"+switchboard.Version)
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return toJSON(proof{Ms: time.Since(start).Milliseconds(), Error: err.Error()})
	}
	probeSize.Store(resp.ContentLength)
	n, rerr := io.Copy(countingDiscard{}, resp.Body)
	resp.Body.Close()
	tr.CloseIdleConnections() // end the flow now so its receipt is written
	p := proof{Bytes: n, Ms: time.Since(start).Milliseconds(), FirstByteMs: first.Milliseconds()}
	if rerr != nil {
		p.Error = rerr.Error()
	} else if resp.StatusCode/100 != 2 {
		p.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
	} else {
		p.OK = true
	}
	// Name the path that carried it: this probe's receipt. The receipt is
	// written when the flow closes, which can trail the body by up to the
	// remote-drain window, so wait for it briefly.
	host := u.Hostname()
	since := start.UnixMilli()
	for deadline := time.Now().Add(3 * time.Second); p.Path == "" && time.Now().Before(deadline); {
		rs := s.Receipts()
		for i := len(rs) - 1; i >= 0; i-- {
			if rs[i].Dst == host && rs[i].At >= since && rs[i].FbMs >= 0 {
				p.Path = rs[i].Path
				break
			}
		}
		if p.Path == "" {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if p.Path != "" {
		for _, ps := range s.Status().Paths {
			if ps.ID == p.Path {
				p.Rail = ps.Rail
			}
		}
	}
	return toJSON(p)
}

// socksConnect opens a SOCKS5 CONNECT through the local switchboard,
// authenticating as user/pass.
func socksConnect(ctx context.Context, socksAddr, user, pass, hostport string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || len(host) > 255 {
		return nil, errors.New("bad target")
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", socksAddr)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	fail := func(e error) (net.Conn, error) { c.Close(); return nil, e }
	if _, err := c.Write([]byte{5, 1, 2}); err != nil {
		return fail(err)
	}
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil || greet[0] != 5 || greet[1] != 2 {
		return fail(errors.New("socks: greeting refused"))
	}
	creds := append([]byte{1, byte(len(user))}, user...)
	creds = append(append(creds, byte(len(pass))), pass...)
	if _, err := c.Write(creds); err != nil {
		return fail(err)
	}
	if _, err := io.ReadFull(c, greet[:]); err != nil || greet[1] != 0 {
		return fail(errors.New("socks: credentials refused"))
	}
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		return fail(err)
	}
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		return fail(err)
	}
	if rep[1] != 0 {
		return fail(fmt.Errorf("socks: connect status %d", rep[1]))
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}
