package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/kilvater"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func h2cTestKey(t *testing.T) (kilvater.Key, string) {
	t.Helper()
	b := make([]byte, 32)
	rand.Read(b)
	s := hex.EncodeToString(b)
	k, err := kilvater.ParseKey(s)
	if err != nil {
		t.Fatal(err)
	}
	return k, s
}

func echoTCP(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln
}

// h2cClient speaks cleartext HTTP/2 to addr, the way a TLS-terminating proxy
// reaches kilvaterd: the HTTP/2 preface over a plain TCP connection.
func h2cClient() *http2.Transport {
	return &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
}

// serveH2C starts kilvaterd's h2c branch on a loopback listener and returns
// its address.
func serveH2C(t *testing.T, srv *kilvater.Server) string {
	t.Helper()
	ln, err := listenPlain("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := &http.Server{Handler: h2c.NewHandler(srv, &http2.Server{IdleTimeout: 120 * time.Second})}
	go httpSrv.Serve(ln)
	t.Cleanup(func() { httpSrv.Close() })
	return ln.Addr().String()
}

// A TLS-terminating proxy reaching kilvaterd over cleartext HTTP/2 can both
// fetch the decoy and carry a full tunnel: the streaming request and response
// bodies the tunnel needs work over h2c.
func TestH2CDecoyAndTunnel(t *testing.T) {
	echo := echoTCP(t)
	key, _ := h2cTestKey(t)
	srv := &kilvater.Server{
		Verifier:     kilvater.NewVerifier([]kilvater.Key{key}),
		Decoy:        http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "a real site") }),
		AllowPrivate: true, // the echo target is on loopback
	}
	addr := serveH2C(t, srv)
	tr := h2cClient()
	defer tr.CloseIdleConnections()

	// Decoy: a visitor without a key.
	resp, err := tr.RoundTrip(mustReq(t, "GET", "http://"+addr+"/", nil, ""))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "a real site" {
		t.Fatalf("decoy body %q", body)
	}

	// Tunnel: a client with a key opens a connection to the echo and gets its
	// bytes back.
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		open := []byte{kilvater.NetTCP}
		open, _ = kilvater.AppendAddr(open, echo.Addr().String())
		kilvater.WriteFrame(pw, kilvater.FrameOpen, open)
		kilvater.WritePad(pw)
		kilvater.WriteFrame(pw, kilvater.FrameData, []byte("hello"))
		kilvater.WriteFrame(pw, kilvater.FrameClose, []byte{0})
	}()
	tag := kilvater.NewTag(key, "/connect", time.Now())
	resp, err = tr.RoundTrip(mustReq(t, "POST", "http://"+addr+"/connect", pr, tag))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tunnel status %d", resp.StatusCode)
	}
	var typ byte
	var data []byte
	for {
		typ, data, err = kilvater.ReadFrame(resp.Body, nil)
		if err != nil {
			t.Fatal(err)
		}
		if typ != kilvater.FramePad {
			break
		}
	}
	if typ != kilvater.FrameData || string(data) != "hello" {
		t.Fatalf("tunnel returned type=%d data=%q, want DATA \"hello\"", typ, data)
	}
}

func mustReq(t *testing.T, method, url string, body io.Reader, tag string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	if tag != "" {
		req.AddCookie(&http.Cookie{Name: kilvater.CookieName, Value: tag})
	}
	return req
}

// listenPlain on a unix: address serves on a socket and replaces a stale one
// left by a past run.
func TestListenPlainUnixSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kilvaterd.sock")
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := listenPlain("unix:" + path)
	if err != nil {
		t.Fatalf("listenPlain unix: %v", err)
	}
	defer ln.Close()
	if ln.Addr().Network() != "unix" {
		t.Fatalf("network %q, want unix", ln.Addr().Network())
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		io.Copy(c, c)
		c.Close()
	}()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer c.Close()
	io.WriteString(c, "ping")
	got := make([]byte, 4)
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "ping" {
		t.Fatalf("echo %q (%v)", got, err)
	}
}
