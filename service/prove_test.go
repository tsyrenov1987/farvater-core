package service

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/switchboard"
)

// socksCarrier is a switchboard that delivers straight to the address asked
// for, speaking the same SOCKS5 with a password.
type socksCarrier struct {
	t          *testing.T
	user, pass string
	to         string // every destination goes here
	receipt    bool
	host       string
}

func (c *socksCarrier) ServeConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	read := func(n int) []byte {
		b := make([]byte, n)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil
		}
		return b
	}
	if g := read(3); g == nil || g[0] != 5 || g[2] != 2 {
		c.t.Errorf("greeting %v", g)
		return
	}
	_, _ = conn.Write([]byte{5, 2})
	h := read(2)
	if h == nil || h[0] != 1 {
		return
	}
	user := read(int(h[1]))
	n := read(1)
	pass := read(int(n[0]))
	if string(user) != c.user || string(pass) != c.pass {
		c.t.Errorf("credentials %q %q", user, pass)
		_, _ = conn.Write([]byte{1, 1})
		return
	}
	_, _ = conn.Write([]byte{1, 0})
	q := read(4)
	if q == nil || q[1] != 1 || q[3] != 3 {
		c.t.Errorf("request %v", q)
		return
	}
	name := read(int(read(1)[0]))
	if string(name) != c.host {
		c.t.Errorf("host %q", name)
	}
	read(2)
	up, err := net.Dial("tcp", c.to)
	if err != nil {
		_, _ = conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	_, _ = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	go func() { _, _ = io.Copy(up, conn); up.Close() }()
	_, _ = io.Copy(conn, up)
}

func (c *socksCarrier) Receipts() []switchboard.ReceiptView {
	if !c.receipt {
		return nil
	}
	return []switchboard.ReceiptView{{Dst: c.host, At: time.Now().UnixMilli() + 1000, FbMs: 12, Path: "p1"}}
}

func (c *socksCarrier) Status() switchboard.Status {
	var st switchboard.Status
	st.Paths = append(st.Paths, switchboard.PathStatus{ID: "p1", Rail: "reality"})
	return st
}

func probeServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	probeRoots = roots
	t.Cleanup(func() { probeRoots = nil })
	return srv, "https://example.com/probe" // httptest's certificate is for example.com
}

func hostport(u string) string { return strings.TrimPrefix(u, "https://") }

func TestProveDelivers(t *testing.T) {
	const size = 256 * 1024
	var ua string
	srv, probe := probeServer(t, func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		w.Header().Set("Content-Length", strconv.Itoa(size))
		_, _ = w.Write(make([]byte, size))
	})
	s := New(t.TempDir(), Hooks{}, t.Logf)
	c := &socksCarrier{t: t, user: "u", pass: "p", to: hostport(srv.URL), receipt: true, host: "example.com"}
	p := s.proveOver(context.Background(), c, "u", "p", probe)
	if !p.OK || p.Bytes != size || p.Path != "p1" || p.Rail != "reality" || p.Error != "" {
		t.Fatalf("%+v", p)
	}
	if ua != "farvater-probe/"+Version {
		t.Fatalf("user agent %q", ua)
	}
	if s.proofRead.Load() != size || s.proofSize.Load() != size {
		t.Fatalf("progress %d of %d", s.proofRead.Load(), s.proofSize.Load())
	}
}

func TestProveSaysWhatFailed(t *testing.T) {
	srv, probe := probeServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) })
	s := New(t.TempDir(), Hooks{}, t.Logf)
	c := &socksCarrier{t: t, user: "u", pass: "p", to: hostport(srv.URL), receipt: true, host: "example.com"}
	if p := s.proveOver(context.Background(), c, "u", "p", probe); p.OK || p.Error != "HTTP 503" {
		t.Fatalf("%+v", p)
	}
	c.to = "127.0.0.1:1"
	if p := s.proveOver(context.Background(), c, "u", "p", probe); p.OK || p.Error == "" {
		t.Fatalf("%+v", p)
	}
	if p := s.proveOver(context.Background(), c, "u", "p", "http://example.com/"); p.OK {
		t.Fatalf("%+v", p)
	}
}

func TestProveStopsWhenTold(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	srv, probe := probeServer(t, func(w http.ResponseWriter, r *http.Request) { <-block })
	s := New(t.TempDir(), Hooks{}, t.Logf)
	c := &socksCarrier{t: t, user: "u", pass: "p", to: hostport(srv.URL), host: "example.com"}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Proof, 1)
	go func() { done <- s.proveOver(ctx, c, "u", "p", probe) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case p := <-done:
		if p.OK {
			t.Fatalf("%+v", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still proving after a cancel")
	}
}
