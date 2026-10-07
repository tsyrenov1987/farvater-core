package kilvater_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/kilvater"
	"golang.org/x/net/http2"
)

func testKey(t *testing.T) kilvater.Key {
	t.Helper()
	b := make([]byte, 32)
	rand.Read(b)
	k, err := kilvater.ParseKey(hex.EncodeToString(b))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &pk.PublicKey, pk)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: pk}
}

func TestDecoyServedToOrdinaryVisitor(t *testing.T) {
	key := testKey(t)
	srv := &kilvater.Server{
		Verifier: kilvater.NewVerifier([]kilvater.Key{key}),
		Decoy:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("welcome")) }),
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Body.String() != "welcome" {
		t.Fatalf("decoy not served: got %q", rec.Body.String())
	}
}

func TestDecoyServedWithBadTag(t *testing.T) {
	key := testKey(t)
	srv := &kilvater.Server{
		Verifier: kilvater.NewVerifier([]kilvater.Key{key}),
		Decoy:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("decoy")) }),
	}
	req := httptest.NewRequest("POST", "/connect", nil)
	req.AddCookie(&http.Cookie{Name: kilvater.CookieName, Value: "garbage"})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Body.String() != "decoy" {
		t.Fatalf("bad tag got tunnel instead of decoy: %q", rec.Body.String())
	}
}

func TestTunnelTCP(t *testing.T) {
	// Start a TCP echo server.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	key := testKey(t)
	srv := &kilvater.Server{
		Verifier: kilvater.NewVerifier([]kilvater.Key{key}),
		Decoy:    http.NotFoundHandler(),
	}

	cert := selfSignedCert(t)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	httpSrv := &http.Server{Handler: srv}
	http2.ConfigureServer(httpSrv, &http2.Server{})
	go httpSrv.Serve(ln)
	defer httpSrv.Close()

	// Connect as a tunnel client via raw HTTP/2.
	pool := x509.NewCertPool()
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	pool.AddCert(leaf)

	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			ServerName: "localhost",
		},
	}

	path := "/connect"
	tag := kilvater.NewTag(key, path, time.Now())

	pr, pw := io.Pipe()

	// Write OPEN frame + DATA frame into request body.
	go func() {
		defer pw.Close()
		body := []byte{kilvater.NetTCP}
		body, _ = kilvater.AppendAddr(body, echo.Addr().String())
		kilvater.WriteFrame(pw, kilvater.FrameOpen, body)
		kilvater.WritePad(pw) // the server must skip this
		kilvater.WriteFrame(pw, kilvater.FrameData, []byte("hello"))
		kilvater.WriteFrame(pw, kilvater.FrameClose, []byte{0})
	}()

	req, _ := http.NewRequest("POST", "https://"+ln.Addr().String()+path, pr)
	req.AddCookie(&http.Cookie{Name: kilvater.CookieName, Value: tag})

	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}

	// Read echoed data back, skipping any PAD the server sent to vary sizes.
	var data []byte
	var typ byte
	for {
		var buf []byte
		typ, data, err = kilvater.ReadFrame(resp.Body, buf)
		if err != nil {
			t.Fatal(err)
		}
		if typ != kilvater.FramePad {
			break
		}
	}
	if typ != kilvater.FrameData || string(data) != "hello" {
		t.Fatalf("expected DATA 'hello', got type=%d data=%q", typ, data)
	}
}

func TestReplayTagRejected(t *testing.T) {
	key := testKey(t)
	v := kilvater.NewVerifier([]kilvater.Key{key})
	path := "/connect"
	tag := kilvater.NewTag(key, path, time.Now())

	if v.Verify(tag, path, time.Now()) < 0 {
		t.Fatal("first use should pass")
	}
	if v.Verify(tag, path, time.Now()) >= 0 {
		t.Fatal("replay should be rejected")
	}
}

func TestExpiredTagRejected(t *testing.T) {
	key := testKey(t)
	v := kilvater.NewVerifier([]kilvater.Key{key})
	path := "/connect"
	tag := kilvater.NewTag(key, path, time.Now().Add(-3*time.Minute))

	if v.Verify(tag, path, time.Now()) >= 0 {
		t.Fatal("expired tag should be rejected")
	}
}

func TestWrongPathRejected(t *testing.T) {
	key := testKey(t)
	v := kilvater.NewVerifier([]kilvater.Key{key})
	tag := kilvater.NewTag(key, "/connect", time.Now())

	if v.Verify(tag, "/other", time.Now()) >= 0 {
		t.Fatal("tag for wrong path should be rejected")
	}
}

func TestFrameRoundTrip(t *testing.T) {
	var buf strings.Builder
	kilvater.WriteFrame(&buf, kilvater.FrameData, []byte("test"))
	typ, body, err := kilvater.ReadFrame(strings.NewReader(buf.String()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if typ != kilvater.FrameData || string(body) != "test" {
		t.Fatalf("got type=%d body=%q", typ, body)
	}
}
