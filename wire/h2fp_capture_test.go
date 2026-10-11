package wire

// A capture of how a client opens an HTTP/2 connection: the frames it sends,
// in order and with their parameters, and the sizes of the TLS records they
// travel in (the part a passive observer sees). It records a real browser's
// profile into testdata/h2fp by hand (TestCaptureBrowserH2), and the tests in
// h2fp_test.go hold our client to that profile.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/tsyrenov1987/farvater-core/kilvater"
)

type h2fpSetting struct {
	ID  uint16 `json:"id"`
	Val uint32 `json:"val"`
}

type h2fpPriority struct {
	Exclusive bool   `json:"exclusive"`
	DependsOn uint32 `json:"depends_on"`
	Weight    int    `json:"weight"` // 1–256, as the RFC counts it
}

type h2fpFrame struct {
	MS        float64        `json:"ms"`
	Type      string         `json:"type"`
	Stream    uint32         `json:"stream,omitempty"`
	Len       int            `json:"len"`
	EndStream bool           `json:"end_stream,omitempty"`
	Ack       bool           `json:"ack,omitempty"`
	Settings  []h2fpSetting  `json:"settings,omitempty"`
	Increment uint32         `json:"increment,omitempty"`
	Priority  *h2fpPriority  `json:"priority,omitempty"`
	Headers   [][2]string    `json:"headers,omitempty"`
	ErrCode   string         `json:"err_code,omitempty"`
	Unknown   map[string]any `json:"unknown,omitempty"`
}

type h2fpRecord struct {
	MS  float64 `json:"ms"`
	Typ byte    `json:"type"`
	Len int     `json:"len"`
}

type h2fpCapture struct {
	Client   string       `json:"client"`
	Captured string       `json:"captured"`
	Records  []h2fpRecord `json:"records"` // client → server, from the first byte
	Frames   []h2fpFrame  `json:"frames"`

	ClientHello string `json:"client_hello"` // the first record's body, hex
}

// recordTap passes reads through and notes the header of every TLS record
// the client sends.
type recordTap struct {
	net.Conn
	start time.Time

	mu      sync.Mutex
	records []h2fpRecord
	hdr     []byte
	skip    int
	hello   []byte // the body of the first record
}

func (r *recordTap) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	r.mu.Lock()
	b := p[:n]
	for len(b) > 0 {
		if r.skip > 0 {
			k := min(r.skip, len(b))
			if len(r.records) == 1 {
				r.hello = append(r.hello, b[:k]...)
			}
			r.skip -= k
			b = b[k:]
			continue
		}
		need := 5 - len(r.hdr)
		k := min(need, len(b))
		r.hdr = append(r.hdr, b[:k]...)
		b = b[k:]
		if len(r.hdr) == 5 {
			l := int(r.hdr[3])<<8 | int(r.hdr[4])
			r.records = append(r.records, h2fpRecord{MS: msSince(r.start), Typ: r.hdr[0], Len: l})
			r.hdr, r.skip = r.hdr[:0], l
		}
	}
	r.mu.Unlock()
	return n, err
}

func (r *recordTap) snapshot() []h2fpRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]h2fpRecord(nil), r.records...)
}

func msSince(t time.Time) float64 {
	return float64(time.Since(t).Microseconds()/100) / 10
}

// h2fpServer answers just enough HTTP/2 for a client to go on sending, and
// writes down everything it receives. Requests are answered once their body
// has arrived, or at once when early is set (a tunnel never ends its body).
type h2fpServer struct {
	early bool
	page  func(path string) (ctype string, body []byte)
	done  string // the request path that ends the capture, linger after it

	linger time.Duration // 1 s when zero
}

func (s *h2fpServer) serve(conn net.Conn, start time.Time, out *h2fpCapture) error {
	pre := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, pre); err != nil {
		return err
	}
	if string(pre) != http2.ClientPreface {
		return errors.New("h2fp: no client preface")
	}
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	fr.MaxHeaderListSize = 1 << 20
	var hbuf bytes.Buffer
	henc := hpack.NewEncoder(&hbuf)
	if err := fr.WriteSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 250}); err != nil {
		return err
	}
	paths := map[uint32]string{}
	respond := func(id uint32) error {
		ctype, body := s.page(paths[id])
		hbuf.Reset()
		henc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		henc.WriteField(hpack.HeaderField{Name: "content-type", Value: ctype})
		henc.WriteField(hpack.HeaderField{Name: "content-length", Value: fmt.Sprint(len(body))})
		henc.WriteField(hpack.HeaderField{Name: "date", Value: time.Now().UTC().Format(http.TimeFormat)})
		if paths[id] == "/" {
			henc.WriteField(hpack.HeaderField{Name: "set-cookie", Value: "_sid=h2fp; Path=/; Secure"})
		}
		if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: hbuf.Bytes(), EndHeaders: true, EndStream: len(body) == 0}); err != nil {
			return err
		}
		if len(body) > 0 {
			return fr.WriteData(id, true, body)
		}
		return nil
	}
	var stop time.Time
	for {
		if !stop.IsZero() {
			conn.SetReadDeadline(stop)
		}
		f, err := fr.ReadFrame()
		if err != nil {
			if !stop.IsZero() {
				return nil
			}
			return err
		}
		h := f.Header()
		e := h2fpFrame{MS: msSince(start), Type: h.Type.String(), Stream: h.StreamID, Len: int(h.Length)}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			e.Ack = f.IsAck()
			f.ForeachSetting(func(st http2.Setting) error {
				e.Settings = append(e.Settings, h2fpSetting{uint16(st.ID), st.Val})
				return nil
			})
			if !f.IsAck() {
				err = fr.WriteSettingsAck()
			}
		case *http2.WindowUpdateFrame:
			e.Increment = f.Increment
		case *http2.PriorityFrame:
			e.Priority = &h2fpPriority{f.Exclusive, f.StreamDep, int(f.Weight) + 1}
		case *http2.MetaHeadersFrame:
			e.EndStream = f.StreamEnded()
			if f.HasPriority() {
				e.Priority = &h2fpPriority{f.Priority.Exclusive, f.Priority.StreamDep, int(f.Priority.Weight) + 1}
			}
			for _, hf := range f.Fields {
				e.Headers = append(e.Headers, [2]string{hf.Name, hf.Value})
			}
			paths[h.StreamID] = f.PseudoValue("path")
			if f.StreamEnded() || s.early {
				err = respond(h.StreamID)
			}
			if paths[h.StreamID] == s.done {
				linger := s.linger
				if linger == 0 {
					linger = time.Second
				}
				stop = time.Now().Add(linger)
			}
		case *http2.DataFrame:
			e.EndStream = f.StreamEnded()
			if n := uint32(len(f.Data())); n > 0 {
				fr.WriteWindowUpdate(0, n)
				if !f.StreamEnded() {
					fr.WriteWindowUpdate(h.StreamID, n)
				}
			}
			if f.StreamEnded() && !s.early {
				err = respond(h.StreamID)
			}
		case *http2.PingFrame:
			e.Ack = f.IsAck()
			if !f.IsAck() {
				err = fr.WritePing(true, f.Data)
			}
		case *http2.RSTStreamFrame:
			e.ErrCode = f.ErrCode.String()
		case *http2.GoAwayFrame:
			e.ErrCode = f.ErrCode.String()
		}
		out.Frames = append(out.Frames, e)
		if err != nil {
			return err
		}
	}
}

func selfSignedCert(t testing.TB, name string) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// captureH2Once records the first connection on ln that completes a TLS
// handshake with ALPN h2. A browser may open and drop a spare connection
// first (a preconnect); those are skipped.
func captureH2Once(t testing.TB, ln net.Listener, srv *h2fpServer) h2fpCapture {
	t.Helper()
	cert := selfSignedCert(t, h2fpHost)
	for {
		raw, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		tap := &recordTap{Conn: raw, start: start}
		tc := tls.Server(tap, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
		if err := tc.Handshake(); err != nil {
			t.Logf("skipped a connection: handshake: %v", err)
			raw.Close()
			continue
		}
		if p := tc.ConnectionState().NegotiatedProtocol; p != "h2" {
			t.Fatalf("ALPN %q, want h2", p)
		}
		var c h2fpCapture
		if err := srv.serve(tc, start, &c); err != nil {
			t.Logf("capture ended: %v", err)
		}
		raw.Close()
		c.Records = tap.snapshot()
		c.ClientHello = hex.EncodeToString(tap.hello)
		c.Captured = time.Now().UTC().Format("2006-01-02")
		return c
	}
}

const h2fpHost = "h2fp.test"

const h2fpPage = `<!doctype html><html><head><title>h2fp</title>
<link rel="stylesheet" href="/s.css"><script src="/a.js"></script></head>
<body><img src="/i.png"><script>
addEventListener('load', async () => {
  await fetch('/connect', {method: 'POST', body: new Uint8Array(300), cache: 'no-store'});
  let n = 0;
  const rs = new ReadableStream({pull(c) { if (n++ < 3) c.enqueue(new Uint8Array(500)); else c.close(); }});
  try { await fetch('/stream', {method: 'POST', body: rs, duplex: 'half', cache: 'no-store'}); } catch (e) {}
  await fetch('/done', {cache: 'no-store'});
});
</script></body></html>`

func h2fpContent(path string) (string, []byte) {
	switch path {
	case "/":
		return "text/html; charset=utf-8", []byte(h2fpPage)
	case "/s.css":
		return "text/css", []byte("body{margin:0}")
	case "/a.js":
		return "text/javascript", []byte("void 0;")
	}
	return "text/plain", []byte("ok")
}

func writeCapture(t testing.TB, path string, c h2fpCapture) {
	t.Helper()
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s (%d frames, %d records)", path, len(c.Frames), len(c.Records))
}

// TestCaptureBrowserH2 records a real browser into testdata/h2fp. By hand:
//
//	KV_H2FP_CAPTURE=testdata/h2fp/chrome.json go test ./wire -run TestCaptureBrowserH2 -v
//
// then open https://h2fp.test:<port>/ in the browser, with the name mapped to
// 127.0.0.1 and the self-signed certificate allowed (Chrome:
// --host-resolver-rules="MAP h2fp.test 127.0.0.1" --ignore-certificate-errors).
// KV_H2FP_PORT fixes the port; KV_H2FP_CLIENT names the browser in the file.
func TestCaptureBrowserH2(t *testing.T) {
	out := os.Getenv("KV_H2FP_CAPTURE")
	if out == "" {
		t.Skip("set KV_H2FP_CAPTURE to record a browser")
	}
	port := os.Getenv("KV_H2FP_PORT")
	if port == "" {
		port = "0"
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	t.Logf("listening on %s; open https://%s:%d/", ln.Addr(), h2fpHost, ln.Addr().(*net.TCPAddr).Port)
	c := captureH2Once(t, ln, &h2fpServer{page: h2fpContent, done: "/done"})
	c.Client = os.Getenv("KV_H2FP_CLIENT")
	writeCapture(t, out, c)
}

// TestCaptureOwnH2 records our own client the same way, over real TLS, so
// its records can be set against the browser's:
//
//	KV_H2FP_OWN=/tmp/own.json go test ./wire -run TestCaptureOwnH2 -v
func TestCaptureOwnH2(t *testing.T) {
	out := os.Getenv("KV_H2FP_OWN")
	if out == "" {
		t.Skip("set KV_H2FP_OWN to record our client")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan h2fpCapture, 1)
	go func() {
		done <- captureH2Once(t, ln, &h2fpServer{early: true, page: h2fpContent, done: "/connect"})
	}()
	spec := PathSpec{ID: "h2fp", Kind: KindKilvater, Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port,
		SNI: h2fpHost, Fingerprint: "chrome", Insecure: true, Key: strings.Repeat("ab", 32), Path: "/connect"}
	w, err := newKilvater(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := w.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// What Run sends first: OPEN, then a PAD.
	ks := sess.(*kilSession)
	open, _ := kilvater.AppendAddr([]byte{kilvater.NetTCP}, "example.com:443")
	kilvater.WriteFrame(ks.conn, kilvater.FrameOpen, open)
	kilvater.WritePad(ks.conn)
	c := <-done
	sess.Close()
	c.Client = "farvater-core kilvater (fp=chrome)"
	writeCapture(t, out, c)
}
