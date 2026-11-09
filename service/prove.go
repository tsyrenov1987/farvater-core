package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/tsyrenov1987/farvater-core/desktop"
	"github.com/tsyrenov1987/farvater-core/switchboard"
)

type counter struct{ n *atomic.Int64 }

func (c counter) Write(b []byte) (int, error) {
	c.n.Add(int64(len(b)))
	return len(b), nil
}

// carrier is the part of the switchboard a delivery test uses.
type carrier interface {
	ServeConn(ctx context.Context, c net.Conn)
	Receipts() []switchboard.ReceiptView
	Status() switchboard.Status
}

// probeRoots is nil outside tests: the system's roots.
var probeRoots *x509.CertPool

func (s *Session) prove(ctx context.Context, sb *switchboard.Switchboard, user, pass, probeURL string) Proof {
	return s.proveOver(ctx, sb, user, pass, probeURL)
}

// proveOver fetches the probe through the switchboard, as every app's traffic
// goes, and says what actually arrived (mobile.ProveDelivery on the phones).
func (s *Session) proveOver(ctx context.Context, sb carrier, user, pass, probeURL string) Proof {
	s.proofRead.Store(0)
	s.proofSize.Store(0)
	u, err := url.Parse(probeURL)
	if err != nil || u.Scheme != "https" {
		return Proof{Error: "probe url must be https"}
	}
	ctx, c := context.WithTimeout(ctx, proofTimeout)
	defer c()
	serve := desktop.Conns(func(ctx context.Context, c net.Conn) { sb.ServeConn(ctx, c) })
	tr := &http.Transport{
		DialContext: func(_ context.Context, _, hostport string) (net.Conn, error) {
			host, p, err := net.SplitHostPort(hostport)
			if err != nil {
				return nil, err
			}
			port, err := strconv.ParseUint(p, 10, 16)
			if err != nil {
				return nil, err
			}
			return desktop.Dial(ctx, serve, user, pass, host, uint16(port))
		},
		TLSClientConfig:   &tls.Config{ServerName: u.Hostname(), RootCAs: probeRoots},
		DisableKeepAlives: true,
	}
	start := time.Now()
	var first atomic.Int64
	trace := &httptrace.ClientTrace{GotFirstResponseByte: func() { first.Store(time.Since(start).Milliseconds()) }}
	req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), "GET", probeURL, nil)
	req.Header.Set("User-Agent", "farvater-probe/"+Version)
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return Proof{Ms: time.Since(start).Milliseconds(), Error: err.Error()}
	}
	s.proofSize.Store(resp.ContentLength)
	n, rerr := io.Copy(counter{&s.proofRead}, resp.Body)
	resp.Body.Close()
	tr.CloseIdleConnections() // end the flow now so its receipt is written
	p := Proof{Bytes: n, Ms: time.Since(start).Milliseconds(), FirstByteMs: first.Load()}
	if rerr != nil {
		p.Error = rerr.Error()
	} else if resp.StatusCode/100 != 2 {
		p.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
	} else {
		p.OK = true
	}
	// Name the path that carried it: the receipt is written when the flow
	// closes, which can trail the body a little.
	host, since := u.Hostname(), start.UnixMilli()
	for deadline := time.Now().Add(3 * time.Second); p.Path == "" && time.Now().Before(deadline); {
		rs := sb.Receipts()
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
		for _, ps := range sb.Status().Paths {
			if ps.ID == p.Path {
				p.Rail = ps.Rail
			}
		}
	}
	return p
}
