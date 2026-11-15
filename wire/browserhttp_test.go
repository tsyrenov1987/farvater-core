package wire

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"
)

// helloLog keeps the ClientHellos a test server saw.
type helloLog struct {
	mu     sync.Mutex
	hellos []*tls.ClientHelloInfo
}

func (l *helloLog) add(h *tls.ClientHelloInfo) {
	l.mu.Lock()
	l.hellos = append(l.hellos, h)
	l.mu.Unlock()
}

func (l *helloLog) all() []*tls.ClientHelloInfo {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]*tls.ClientHelloInfo(nil), l.hellos...)
}

const extPreSharedKey = 41

func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

// browserTestServer is an HTTPS server for name (h2 or http/1.1 only) and a
// BrowserTransport that reaches it at that name.
func browserTestServer(t *testing.T, name string, h2 bool) (*BrowserTransport, *helloLog) {
	t.Helper()
	cert := selfSignedCert(t, name)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	log := &helloLog{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resumed := r.TLS != nil && r.TLS.DidResume
		io.WriteString(w, r.Proto+" resumed="+strconv.FormatBool(resumed)+" ua="+r.UserAgent())
	}))
	srv.EnableHTTP2 = h2
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			log.add(h)
			return nil, nil
		},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	tr := &BrowserTransport{
		RootCAs: roots,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	return tr, log
}

func browserGet(t *testing.T, tr http.RoundTripper, url string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "farvater-core/test")
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestBrowserTransportIsChrome: the request goes over HTTP/2 when the server
// offers it, with Chrome's ClientHello (GREASE first, Chrome's ALPN), and the
// request's own headers reach the server.
func TestBrowserTransportIsChrome(t *testing.T) {
	tr, log := browserTestServer(t, "h2.browser.test", true)
	if got := browserGet(t, tr, "https://h2.browser.test/c"); got != "HTTP/2.0 resumed=false ua=farvater-core/test" {
		t.Fatalf("body = %q", got)
	}
	hs := log.all()
	if len(hs) != 1 {
		t.Fatalf("%d ClientHellos, want 1", len(hs))
	}
	h := hs[0]
	if !isGREASE(h.CipherSuites[0]) {
		t.Errorf("first cipher suite %#04x is not GREASE: not Chrome's ClientHello", h.CipherSuites[0])
	}
	if !slices.Equal(h.SupportedProtos, []string{"h2", "http/1.1"}) {
		t.Errorf("ALPN = %q, want Chrome's [h2 http/1.1]", h.SupportedProtos)
	}
	if h.ServerName != "h2.browser.test" {
		t.Errorf("SNI = %q", h.ServerName)
	}
	if slices.Contains(h.Extensions, extPreSharedKey) {
		t.Error("first ClientHello to a name offers a session it cannot have")
	}
}

// TestBrowserTransportHTTP11: a server without HTTP/2 gets HTTP/1.1 on the
// same Chrome connection.
func TestBrowserTransportHTTP11(t *testing.T) {
	tr, log := browserTestServer(t, "h1.browser.test", false)
	if got := browserGet(t, tr, "https://h1.browser.test/c"); got != "HTTP/1.1 resumed=false ua=farvater-core/test" {
		t.Fatalf("body = %q", got)
	}
	if hs := log.all(); len(hs) != 1 || !isGREASE(hs[0].CipherSuites[0]) {
		t.Fatalf("ClientHellos = %d, want one of Chrome's", len(hs))
	}
}

// TestBrowserTransportResumes: the second request to a name resumes the
// session the first one got, with pre_shared_key last in the ClientHello, as
// Chrome coming back to a site does (F-129).
func TestBrowserTransportResumes(t *testing.T) {
	tr, log := browserTestServer(t, "resume.browser.test", true)
	browserGet(t, tr, "https://resume.browser.test/1")
	if got := browserGet(t, tr, "https://resume.browser.test/2"); got != "HTTP/2.0 resumed=true ua=farvater-core/test" {
		t.Fatalf("second request: %q, want a resumed session", got)
	}
	hs := log.all()
	if len(hs) != 2 {
		t.Fatalf("%d ClientHellos, want 2", len(hs))
	}
	if slices.Contains(hs[0].Extensions, extPreSharedKey) {
		t.Error("first ClientHello carries pre_shared_key")
	}
	ext := hs[1].Extensions
	if len(ext) == 0 || ext[len(ext)-1] != extPreSharedKey {
		t.Errorf("second ClientHello extensions %v: pre_shared_key is not last", ext)
	}
	if !isGREASE(hs[1].CipherSuites[0]) {
		t.Error("the resuming ClientHello is not Chrome's")
	}
}

// TestPathTLSResumes: a path with real TLS (kilvater, XHTTP, gRPC, and
// WebSocket's http/1.1 variant) resumes its session on the next connection
// for each browser profile; the first ClientHello stays the browser's first.
func TestPathTLSResumes(t *testing.T) {
	for _, fp := range []string{"chrome", "edge", "firefox"} {
		for _, http11 := range []bool{false, true} {
			t.Run(fp+"/http11="+strconv.FormatBool(http11), func(t *testing.T) {
				name := fp + strconv.FormatBool(http11) + ".path.test"
				cert := selfSignedCert(t, name)
				log := &helloLog{}
				resumed := make(chan bool, 4)
				ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
					Certificates: []tls.Certificate{cert},
					NextProtos:   []string{"h2", "http/1.1"},
					GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
						log.add(h)
						return nil, nil
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				go func() {
					for {
						c, err := ln.Accept()
						if err != nil {
							return
						}
						go func() {
							defer c.Close()
							tc := c.(*tls.Conn)
							if tc.Handshake() != nil {
								resumed <- false
								return
							}
							resumed <- tc.ConnectionState().DidResume
							c.Write([]byte{1})
							io.Copy(io.Discard, c)
						}()
					}
				}()
				port := ln.Addr().(*net.TCPAddr).Port
				spec := PathSpec{Host: "127.0.0.1", Port: port, Security: "tls", SNI: name, Fingerprint: fp, Insecure: true}
				for i := range 2 {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					u, err := dialSecure(ctx, spec, http11)
					cancel()
					if err != nil {
						t.Fatalf("dial %d: %v", i, err)
					}
					var b [1]byte
					if _, err := io.ReadFull(u, b[:]); err != nil { // takes in the ticket
						t.Fatalf("read %d: %v", i, err)
					}
					u.Close()
					if got := <-resumed; got != (i == 1) {
						t.Fatalf("connection %d resumed = %v", i, got)
					}
				}
				hs := log.all()
				if slices.Contains(hs[0].Extensions, extPreSharedKey) {
					t.Error("first ClientHello carries pre_shared_key")
				}
				if ext := hs[1].Extensions; ext[len(ext)-1] != extPreSharedKey {
					t.Errorf("second ClientHello: pre_shared_key not last in %v", ext)
				}
				want := []string{"h2", "http/1.1"}
				if http11 {
					want = []string{"http/1.1"}
				}
				for i, h := range hs {
					if !slices.Equal(h.SupportedProtos, want) {
						t.Errorf("hello %d ALPN = %q, want %q", i, h.SupportedProtos, want)
					}
				}
			})
		}
	}
}

// TestBrowserTransportByAddress: a URL with an IP address (the DoH resolvers
// at 1.1.1.1 and 8.8.8.8) sends no SNI, as Chrome does, and the certificate
// is checked against that address.
func TestBrowserTransportByAddress(t *testing.T) {
	log := &helloLog{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	srv.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		log.add(h)
		return nil, nil
	}}
	srv.StartTLS() // the test certificate is for 127.0.0.1
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	if got := browserGet(t, &BrowserTransport{RootCAs: roots}, srv.URL+"/dns-query"); got != "ok" {
		t.Fatalf("body = %q", got)
	}
	hs := log.all()
	if len(hs) != 1 || hs[0].ServerName != "" || !isGREASE(hs[0].CipherSuites[0]) {
		t.Fatalf("ClientHellos %d, SNI %q: want one of Chrome's without SNI", len(hs), hs[0].ServerName)
	}
}
