package switchboard

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/tsyrenov1987/farvater-core/brain"
	"github.com/tsyrenov1987/farvater-core/wire"
)

// sweepDue starts the sweep the brain asks for, if any (brain/sweep.go). It
// runs with s.mu held.
func (s *Switchboard) sweepDue(now int64) {
	if s.cfg.ProbeURL == "" {
		return
	}
	paths := s.b.SweepDue(now)
	if len(paths) == 0 {
		return
	}
	go s.sweep(paths)
}

// sweep fetches the probe over each of paths at once, each a flow pinned to
// its path, and lets the brain decide as they come in.
func (s *Switchboard) sweep(paths []string) {
	s.mu.Lock()
	ctx := s.life
	s.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	for _, p := range paths {
		go func() {
			bytes, ms, whole := s.probeOver(ctx, p)
			s.mu.Lock()
			s.b.Swept(p, bytes, ms, whole, nowMs())
			s.mu.Unlock()
			s.logf("sweep %s: %d bytes in %d ms, whole %v", p, bytes, ms, whole)
		}()
	}
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-t.C:
		case <-ctx.Done():
			return
		}
		s.mu.Lock()
		out := s.b.SweepCheck(nowMs())
		s.mu.Unlock()
		if !out {
			return
		}
	}
}

// probeRoots, when set (only by the chaos lab's build), verify the probe's
// certificate instead of the system's roots.
var probeRoots *x509.CertPool

// probeOver fetches s.cfg.ProbeURL over path, as an app's flow that only
// path may carry: its receipt goes to the brain as any flow's does. It
// returns the body bytes read, the time from the dial (its pacing waited out)
// to the end, and whether the body came in whole.
func (s *Switchboard) probeOver(ctx context.Context, path string) (int64, int64, bool) {
	u, err := url.Parse(s.cfg.ProbeURL)
	if err != nil || u.Scheme != "https" {
		return 0, 0, false
	}
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}
	ctx, cancel := context.WithTimeout(ctx, brain.ProbeCapMs*time.Millisecond)
	defer cancel()
	app, door := net.Pipe()
	f := &flow{s: s, client: door, target: wire.Target{Host: u.Hostname(), Port: port}, class: classify(port),
		up: make(chan []byte, 8), done: make(chan struct{}), pin: path}
	go func() {
		// The first payload rides with the proxy request, as handle does it.
		_ = door.SetReadDeadline(time.Now().Add(s.cfg.FirstPayloadWait))
		buf := make([]byte, 16*1024)
		n, _ := door.Read(buf)
		_ = door.SetReadDeadline(time.Time{})
		f.prelude = append([]byte(nil), buf[:n]...)
		go f.readLoop()
		f.serve(ctx)
	}()
	used := false
	tr := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if used {
				return nil, net.ErrClosed
			}
			used = true
			return app, nil
		},
		TLSClientConfig:   &tls.Config{RootCAs: probeRoots},
		DisableKeepAlives: true, ForceAttemptHTTP2: false,
	}
	defer tr.CloseIdleConnections()
	defer app.Close()
	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, "GET", s.cfg.ProbeURL, nil)
	req.Header.Set("User-Agent", "farvater-probe/"+Version)
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return 0, time.Since(start).Milliseconds(), false
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	whole := err == nil && resp.StatusCode == http.StatusOK && (resp.ContentLength < 0 || n == resp.ContentLength)
	return n, time.Since(start).Milliseconds(), whole
}
