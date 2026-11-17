// Command kbbench measures one path on its own, with no brain in the way: it
// builds the wire of a single link (kilvater://, vkturn://, kilbond://), and
// downloads or uploads a body through it, a few times in a row. It prints the
// goodput, the time to the first byte, the stalls and, for a bond, what each
// leg carried — the numbers the kilbond audit compares before and after a fix.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tsyrenov1987/farvater-core/wire"
)

type runConn struct {
	ctx    context.Context
	cancel context.CancelFunc
	up     chan []byte
	pr     *io.PipeReader
	done   chan struct{} // the session's Run has returned
}

type noMeter struct{}

func (noMeter) Up([]byte)   {}
func (noMeter) Down([]byte) {}

func newRunConn(ctx context.Context, sess wire.Session, target wire.Target) *runConn {
	ctx, cancel := context.WithCancel(ctx)
	pr, pw := io.Pipe()
	c := &runConn{ctx: ctx, cancel: cancel, up: make(chan []byte, 16), pr: pr, done: make(chan struct{})}
	go func() {
		defer close(c.done)
		_, err := sess.Run(ctx, target, nil, c.up, pw, noMeter{})
		if err == nil {
			err = io.EOF
		}
		pw.CloseWithError(err)
	}()
	return c
}

func (c *runConn) Read(p []byte) (int, error) { return c.pr.Read(p) }
func (c *runConn) Write(p []byte) (int, error) {
	select {
	case c.up <- append([]byte(nil), p...):
		return len(p), nil
	case <-c.ctx.Done():
		return 0, net.ErrClosed
	}
}
func (c *runConn) Close() error                     { c.cancel(); return c.pr.Close() }
func (c *runConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *runConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *runConn) SetDeadline(time.Time) error      { return nil }
func (c *runConn) SetReadDeadline(time.Time) error  { return nil }
func (c *runConn) SetWriteDeadline(time.Time) error { return nil }

// gaps counts the pauses in a stream of progress marks.
type gaps struct {
	mu       sync.Mutex
	last     time.Time
	first    time.Duration
	start    time.Time
	stalls   int
	maxGap   time.Duration
	stallMin time.Duration
}

func (g *gaps) mark() {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if g.last.IsZero() {
		g.first = now.Sub(g.start)
	} else if d := now.Sub(g.last); d > g.maxGap {
		g.maxGap = d
	}
	if !g.last.IsZero() && now.Sub(g.last) >= g.stallMin {
		g.stalls++
	}
	g.last = now
}

type countR struct {
	r io.Reader
	g *gaps
	n int64
}

func (c *countR) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.n += int64(n)
		c.g.mark()
	}
	return n, err
}

// zeros is an upload body of n bytes that marks progress as it is taken.
type zeros struct {
	left int64
	g    *gaps
}

func (z *zeros) Read(p []byte) (int, error) {
	if z.left <= 0 {
		return 0, io.EOF
	}
	if len(p) > 16<<10 {
		p = p[:16<<10]
	}
	if int64(len(p)) > z.left {
		p = p[:z.left]
	}
	for i := range p {
		p[i] = byte(i * 131)
	}
	z.left -= int64(len(p))
	z.g.mark()
	return len(p), nil
}

type result struct {
	Run    int                 `json:"run"`
	OK     bool                `json:"ok"`
	Err    string              `json:"err,omitempty"`
	Bytes  int64               `json:"bytes"`
	Secs   float64             `json:"secs"`
	KBps   float64             `json:"kbps"`
	DialMs int64               `json:"dial_ms"`
	TTFBMs int64               `json:"ttfb_ms"`
	Stalls int                 `json:"stalls"`
	MaxGap int64               `json:"max_gap_ms"`
	Legs   map[string][2]int64 `json:"legs,omitempty"`   // leg -> down, up bytes this run
	LegEv  map[string][3]int64 `json:"leg_ev,omitempty"` // leg -> fail, drop, back this run
	Bond   []wire.BondLegStat  `json:"bond,omitempty"`   // the legs' counts since the process began
}

func main() {
	link := flag.String("link", "", "the path's link, or @file holding it")
	mode := flag.String("mode", "down", "down | up")
	size := flag.Int64("bytes", 20_000_000, "body size")
	n := flag.Int("n", 5, "runs")
	pause := flag.Duration("pause", 10*time.Second, "pause between runs")
	timeout := flag.Duration("timeout", 180*time.Second, "one run's limit")
	host := flag.String("host", "speed.cloudflare.com", "the measuring host (https)")
	quotaMax := flag.Int("quota", 0, "instead of a run: open up to this many allocations per TURN credential and say where the relay stops")
	quotaPool := flag.String("pool", "", "with -quota: a directory of pool q*.json accounts to ask instead of the link's")
	flag.Parse()
	raw := *link
	if strings.HasPrefix(raw, "@") {
		b, err := os.ReadFile(raw[1:])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		raw = strings.TrimSpace(string(b))
	}
	spec, err := wire.ParseURI(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "link:", err)
		os.Exit(2)
	}
	if *quotaMax > 0 {
		quota(spec, *quotaMax, time.Second, *quotaPool)
		return
	}
	w, err := wire.Build(spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "build:", err)
		os.Exit(2)
	}
	// An interrupt ends the run in hand, and the relays are let go on the way out.
	root, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	enc := json.NewEncoder(os.Stdout)
	for i := 1; i <= *n && root.Err() == nil; i++ {
		enc.Encode(one(root, w, i, *mode, *host, *size, *timeout))
		if i < *n {
			select {
			case <-time.After(*pause):
			case <-root.Done():
			}
		}
	}
	w.Close()
	wire.CloseTURNTunnels()
	time.Sleep(300 * time.Millisecond) // the relays' answers to the release
}

func legs(w wire.Wire) map[string]wire.BondLegStat {
	bs, ok := w.(wire.BondStater)
	if !ok {
		return nil
	}
	out := map[string]wire.BondLegStat{}
	for _, l := range bs.BondStats() {
		out[l.Leg] = l
	}
	return out
}

func one(root context.Context, w wire.Wire, run int, mode, host string, size int64, limit time.Duration) (res result) {
	res.Run = run
	ctx, cancel := context.WithTimeout(root, limit)
	defer cancel()
	before := legs(w)
	g := &gaps{start: time.Now(), stallMin: time.Second}
	var rc *runConn
	defer func() {
		res.Secs = time.Since(g.start).Seconds()
		if rc != nil { // a bond counts its legs when the flow has ended
			rc.Close()
			select {
			case <-rc.done:
			case <-time.After(3 * time.Second):
			}
		}
		if res.Secs > 0 {
			res.KBps = float64(res.Bytes) / 1024 / res.Secs
		}
		res.TTFBMs, res.Stalls, res.MaxGap = g.first.Milliseconds(), g.stalls, g.maxGap.Milliseconds()
		if bs, ok := w.(wire.BondStater); ok {
			res.Bond = bs.BondStats()
		}
		if after := legs(w); after != nil {
			res.Legs, res.LegEv = map[string][2]int64{}, map[string][3]int64{}
			for k, a := range after {
				b := before[k]
				res.Legs[k] = [2]int64{a.Down - b.Down, a.Up - b.Up}
				res.LegEv[k] = [3]int64{a.Fails - b.Fails, a.Drops - b.Drops, a.Backs - b.Backs}
			}
		}
	}()
	sess, err := w.Dial(ctx)
	res.DialMs = time.Since(g.start).Milliseconds()
	if err != nil {
		res.Err = "dial: " + err.Error()
		return
	}
	defer sess.Close()
	rc = newRunConn(ctx, sess, wire.Target{Host: host, Port: 443})
	defer rc.Close()
	tc := tls.Client(rc, &tls.Config{ServerName: host, NextProtos: []string{"http/1.1"}})
	tr := &http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return tc, nil }, DisableKeepAlives: true}
	var req *http.Request
	var body *zeros
	if mode == "up" {
		body = &zeros{left: size, g: g}
		req, _ = http.NewRequestWithContext(ctx, "POST", "https://"+host+"/__up", body)
		req.ContentLength = size
		req.Header.Set("Content-Type", "application/octet-stream")
	} else {
		req, _ = http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/__down?bytes=%d", host, size), nil)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := tr.RoundTrip(req)
	if err != nil {
		res.Err = "http: " + err.Error()
		if mode == "up" {
			res.Bytes = size - body.left
		}
		return
	}
	defer resp.Body.Close()
	if mode == "up" {
		io.Copy(io.Discard, resp.Body)
		res.Bytes = size
		res.OK = resp.StatusCode == 200
		if !res.OK {
			res.Err = resp.Status
		}
		return
	}
	cr := &countR{r: resp.Body, g: g}
	_, err = io.Copy(io.Discard, cr)
	res.Bytes = cr.n
	res.OK = err == nil && resp.StatusCode == 200 && cr.n == size
	if err != nil {
		res.Err = "body: " + err.Error()
	} else if !res.OK {
		res.Err = fmt.Sprintf("%s, %d bytes", resp.Status, cr.n)
	}
	return
}
