package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kv.example.org"},
		DNSNames:     []string{"kv.example.org"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
	}
}

// startServer serves the way main does: listenTLS + http.Server + h2.
func startServer(t *testing.T) string {
	t.Helper()
	ln, err := listenTLS("127.0.0.1:0", testTLSConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "decoy "+r.Proto)
	})}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// A plain-HTTP request must not be answered with net/http's Go-only line.
func TestPlainHTTPGetsNoGoSignature(t *testing.T) {
	addr := startServer(t)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: kv.example.org\r\n\r\n")
	got, _ := io.ReadAll(c)
	if len(got) != 0 {
		t.Fatalf("plain HTTP got a reply %q; want the connection closed without a word", got)
	}
	if strings.Contains(string(got), "HTTPS server") {
		t.Fatal("Go signature leaked")
	}
}

// TLS clients still reach the handler over HTTP/2, and a stalled plain
// connection does not hold them up.
func TestTLSStillServesH2(t *testing.T) {
	addr := startServer(t)
	stall, err := net.Dial("tcp", addr) // never says anything
	if err != nil {
		t.Fatal(err)
	}
	defer stall.Close()

	tr := &http2.Transport{TLSClientConfig: &tls.Config{ServerName: "kv.example.org", InsecureSkipVerify: true}}
	cl := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	for i := 0; i < 3; i++ {
		resp, err := cl.Get("https://" + addr + "/")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != "decoy HTTP/2.0" {
			t.Fatalf("body %q", b)
		}
	}
}
