package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/tsyrenov1987/farvater-core/wire"
)

// probe opens one HTTPS fetch through every path of the catalogue and prints
// what each one actually delivered. It is a diagnostic, not a selector.
func cmdProbe(args []string) {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	src := fs.String("catalogue", "", "catalogue URL or file")
	target := fs.String("url", "", "URL to fetch through each path (default: the catalogue's probe_urls[0], else a 256 KiB object)")
	timeout := fs.Duration("timeout", 15*time.Second, "per-path time limit")
	_ = fs.Parse(args)
	cat := loadCatalogue(*src)
	u := *target
	if u == "" {
		if len(cat.ProbeURLs) > 0 {
			u = cat.ProbeURLs[0]
		} else {
			u = "https://speed.cloudflare.com/__down?bytes=262144"
		}
	}
	pu, err := url.Parse(u)
	if err != nil || pu.Scheme != "https" {
		fmt.Fprintln(os.Stderr, "probe: -url must be https")
		os.Exit(2)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "PATH\tRAIL\tWIRE\tFIRSTBYTE\tBYTES\tTOTAL\tHTTP\tRESULT")
	for _, e := range cat.Paths {
		w, err := wire.Build(e.Spec)
		if err != nil {
			fmt.Fprintf(tw, "%s\t%s\t-\t-\t-\t-\t-\tunsupported: %v\n", e.ID, e.Spec.Rail(), err)
			continue
		}
		r := probeOne(w, pu, *timeout)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%dms\t%s\t%s\n", e.ID, e.Spec.Rail(), ms(r.wireMs), ms(r.fbMs), r.bytes, r.totalMs, r.status, r.result)
		tw.Flush()
		w.Close()
	}
}

func ms(v int64) string {
	if v < 0 {
		return "-"
	}
	return strconv.FormatInt(v, 10) + "ms"
}

type probeResult struct {
	wireMs, fbMs, totalMs int64
	bytes                 int64
	status                string
	result                string
}

type probeMeter struct {
	mu      sync.Mutex
	start   time.Time
	firstMs int64
	down    int64
}

func (m *probeMeter) Up([]byte) {}
func (m *probeMeter) Down(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.firstMs == 0 {
		m.firstMs = time.Since(m.start).Milliseconds()
		if m.firstMs == 0 {
			m.firstMs = 1
		}
	}
	m.down += int64(n)
}

// appConn is the "app side" of a session: writes go to the up channel, reads
// come from the pipe the session writes into.
type appConn struct {
	up     chan []byte
	r      *io.PipeReader
	closed chan struct{}
	once   sync.Once
}

func (c *appConn) Read(b []byte) (int, error) { return c.r.Read(b) }
func (c *appConn) Write(b []byte) (int, error) {
	p := append([]byte(nil), b...)
	select {
	case c.up <- p:
		return len(b), nil
	case <-c.closed:
		return 0, io.ErrClosedPipe
	}
}
func (c *appConn) Close() error {
	c.once.Do(func() { close(c.up); close(c.closed) })
	return nil
}
func (c *appConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *appConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *appConn) SetDeadline(time.Time) error      { return nil }
func (c *appConn) SetReadDeadline(time.Time) error  { return nil }
func (c *appConn) SetWriteDeadline(time.Time) error { return nil }

func probeOne(w wire.Wire, u *url.URL, timeout time.Duration) probeResult {
	res := probeResult{wireMs: -1, fbMs: -1}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	t0 := time.Now()
	sess, err := w.Dial(ctx)
	if err != nil {
		res.totalMs = time.Since(t0).Milliseconds()
		res.result = "dial: " + err.Error()
		return res
	}
	res.wireMs = time.Since(t0).Milliseconds()

	host := u.Hostname()
	port := 443
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	pr, pw := io.Pipe()
	ac := &appConn{up: make(chan []byte, 8), r: pr, closed: make(chan struct{})}
	m := &probeMeter{start: t0}
	type runRes struct {
		out wire.Outcome
		err error
	}
	done := make(chan runRes, 1)
	go func() {
		out, err := sess.Run(ctx, wire.Target{Host: host, Port: port}, nil, ac.up, pw, m)
		if err != nil {
			pw.CloseWithError(err)
		} else {
			pw.Close()
		}
		done <- runRes{out, err}
	}()

	tc := tls.Client(ac, &tls.Config{ServerName: host, NextProtos: []string{"http/1.1"}})
	status, n, ferr := fetch(ctx, tc, u)
	tc.Close()
	ac.Close()
	// Break the downstream pipe so any write still pending inside the session
	// fails fast instead of blocking forever now that nobody reads it.
	pr.CloseWithError(io.ErrClosedPipe)
	cancel()
	var rr runRes
	select {
	case rr = <-done:
	case <-time.After(3 * time.Second):
		rr = runRes{wire.OutcomeCanceled, context.DeadlineExceeded}
	}
	res.totalMs = time.Since(t0).Milliseconds()
	m.mu.Lock()
	res.fbMs = m.firstMs
	if res.fbMs == 0 {
		res.fbMs = -1
	}
	m.mu.Unlock()
	res.bytes = n
	res.status = status
	switch {
	case ferr == nil:
		// The fetch delivered a full HTTP response through the path; the
		// session teardown reason after that is not interesting.
		res.result = "ok"
	case errors.Is(rr.err, wire.ErrWireDead):
		res.result = "wire dead"
	case rr.out == wire.OutcomeError && rr.err != nil:
		res.result = "session: " + rr.err.Error()
	default:
		res.result = "fetch: " + ferr.Error()
	}
	return res
}

func fetch(ctx context.Context, tc *tls.Conn, u *url.URL) (string, int64, error) {
	if err := tc.HandshakeContext(ctx); err != nil {
		return "-", 0, err
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	req.Header.Set("User-Agent", "farvater-probe/0.1")
	req.Header.Set("Connection", "close")
	if err := req.Write(tc); err != nil {
		return "-", 0, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), req)
	if err != nil {
		return "-", 0, err
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	return resp.Status, n, err
}
