//go:build chaos

// Package chaos runs the real core (package mobile) against paths served in
// process, each behind a proxy that injects the faults met in the field:
// resets on the ClientHello, black holes, resets and 16 KB freezes in the
// middle of a download, throttling, added latency, flaky connections. It is
// built for a phone (gomobile bind ./devtest/chaos) so the core runs on the
// device's own CPU and network stack; nothing here ships in the apps.
package chaos

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tsyrenov1987/farvater-core/kilvater"
)

// Fault is what a path's proxy does to the connections it carries.
type Fault int32

const (
	OK          Fault = iota
	Refuse            // reset at once, before any byte
	RstHello          // read the ClientHello, then reset (TSPU on SNI)
	Blackhole         // accept and read, never answer
	RstMid            // reset after rstMidBytes downstream
	Freeze16K         // stop forwarding downstream after 16 KB, keep the connection open
	Throttle          // downstream at throttleBps
	Latency           // latencyMs added to each downstream burst (an answer after a pause)
	Flaky             // a share flakyShare of connections is reset after the hello
	UpRst             // reset after upRstBytes upstream (an upload cut)
	UpFreeze          // stop taking upstream after freezeBytes (writes block), keep the connection open
	Jitter            // random pauses up to jitterMs before downstream bursts (loss and retransmits)
	ThrottleRst       // throttled, and reset after rstMidBytes downstream
	FreezeLive        // live connections stop downstream at once; new ones freeze after freezeBytes
	RstLive           // live connections are reset at once; new ones are reset after the hello
)

var faultNames = map[Fault]string{OK: "ok", Refuse: "refuse", RstHello: "rst_hello", Blackhole: "blackhole",
	RstMid: "rst_mid", Freeze16K: "freeze16k", Throttle: "throttle", Latency: "latency", Flaky: "flaky",
	UpRst: "up_rst", UpFreeze: "up_freeze", Jitter: "jitter", ThrottleRst: "throttle_rst", FreezeLive: "freeze_live", RstLive: "rst_live"}

func (f Fault) String() string { return faultNames[f] }

const (
	rstMidBytes = 48 << 10
	freezeBytes = 16 << 10
	throttleBps = 16 << 10
	latencyMs   = 350
	flakyShare  = 0.3
	upRstBytes  = 64 << 10
	jitterMs    = 600
	jitterShare = 0.3
)

// path is one in-process server (VLESS or Trojan over TLS) and its proxy.
type path struct {
	id     string
	kind   string // vless | trojan
	host   string // the proxy's address: paths on two addresses, as nodes are
	fault  atomic.Int32
	conns  atomic.Int64 // connections the proxy accepted
	epoch  atomic.Int64 // bumped when the network drops every live connection silently
	server net.Listener
	proxy  net.Listener
	// a Hysteria 2 path: its server and the UDP relay in front
	udpServer, udpProxy net.PacketConn
}

func (p *path) port() int {
	if p.udpProxy != nil {
		return p.udpProxy.LocalAddr().(*net.UDPAddr).Port
	}
	return p.proxy.Addr().(*netAddr).Port
}

func (p *path) set(f Fault) { p.fault.Store(int32(f)) }
func (p *path) get() Fault  { return Fault(p.fault.Load()) }

type lab struct {
	paths  []*path
	origin net.Listener
	cert   tls.Certificate
	uuid   [16]byte
	pass   string
	kilKey kilvater.Key
	kilHex string
	wg     sync.WaitGroup
	closed atomic.Bool
}

func newLab(n int, kinds []string) (*lab, error) {
	l := &lab{pass: "chaos-lab"}
	rand.Read(l.uuid[:])
	cert, err := selfSigned()
	if err != nil {
		return nil, err
	}
	l.cert = cert
	if err := l.kilSetup(); err != nil {
		return nil, err
	}
	// the origin speaks HTTPS, as apps' sites do: the core judges stalls by
	// the TLS records it sees inside a flow
	if l.origin, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}}); err != nil {
		return nil, err
	}
	go (&http.Server{Handler: http.HandlerFunc(serveBytes), ReadHeaderTimeout: 10 * time.Second}).Serve(l.origin)
	for i := 0; i < n; i++ {
		kind := []string{"vless", "trojan"}[i%2]
		if i < len(kinds) {
			kind = kinds[i]
		}
		p := &path{id: fmt.Sprintf("p%d", i), kind: kind, host: []string{"127.0.0.1", "::1"}[i/3]}
		if kind == "hy2" {
			p.host = "127.0.0.1" // the QUIC client does not reach a UDP relay on ::1 here
		}
		l.paths = append(l.paths, p)
		if kind == "hy2" {
			if err := l.startHy2(p); err != nil {
				l.close()
				return nil, err
			}
			continue
		}
		cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
		if kind == "kilvater" {
			cfg.NextProtos = []string{"h2"}
		}
		if p.server, err = tls.Listen("tcp", "127.0.0.1:0", cfg); err != nil {
			l.close()
			return nil, err
		}
		if p.proxy, err = net.Listen("tcp", net.JoinHostPort(p.host, "0")); err != nil {
			l.close()
			return nil, err
		}
		if kind == "kilvater" {
			go l.serveKilvater(p)
		} else {
			go l.serve(p)
		}
		go l.relay(p)
	}
	return l, nil
}

func (l *lab) close() {
	l.closed.Store(true)
	if l.origin != nil {
		l.origin.Close()
	}
	for _, p := range l.paths {
		for _, c := range []io.Closer{p.server, p.proxy, p.udpServer, p.udpProxy} {
			if c != nil && !reflect.ValueOf(c).IsNil() {
				c.Close()
			}
		}
	}
}

// catalogue lists the paths as share links; net, if set, labels path i.
func (l *lab) catalogue(labels map[int]string) string {
	var s string
	for i, p := range l.paths {
		if n := labels[i]; n != "" {
			s += "#net=" + n + "\n"
		}
		// each path its own SNI, as nodes have: the core paces handshakes per SNI and per IP
		hp := net.JoinHostPort(p.host, strconv.Itoa(p.port()))
		q := fmt.Sprintf("security=tls&sni=%s.chaos.test&fp=chrome&allowInsecure=1&type=tcp#%s", p.id, p.id)
		switch p.kind {
		case "kilvater":
			s += fmt.Sprintf("kilvater://%s@%s/connect?sni=%s.chaos.test&fp=chrome#%s\n", l.kilHex, hp, p.id, p.id)
		case "hy2":
			s += fmt.Sprintf("hysteria2://%s@%s/?sni=%s.chaos.test&insecure=1#%s\n", l.pass, hp, p.id, p.id)
		case "vless":
			s += fmt.Sprintf("vless://%s@%s?%s\n", uuidText(l.uuid), hp, q)
		default:
			s += fmt.Sprintf("trojan://%s@%s?%s\n", l.pass, hp, q)
		}
	}
	return s
}

// catalogueJSON lists the paths as the JSON catalogue, with the paths in
// white marked as entering through an allow-listed address.
func (l *lab) catalogueJSON(white map[int]bool) string {
	type entry struct {
		ID     string         `json:"id"`
		URI    string         `json:"uri"`
		Labels map[string]any `json:"labels"`
	}
	var paths []entry
	for i, line := range strings.Split(strings.TrimSpace(l.catalogue(nil)), "\n") {
		e := entry{ID: l.paths[i].id, URI: line, Labels: map[string]any{}}
		if white[i] {
			e.Labels["white"] = true
		}
		paths = append(paths, e)
	}
	b, _ := json.Marshal(map[string]any{"v": 1, "paths": paths})
	return string(b)
}

type netAddr = net.TCPAddr

func uuidText(u [16]byte) string {
	h := hex.EncodeToString(u[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// serveBytes answers /bytes?n=N with N bytes; a POST's body is read whole
// first (an upload).
func serveBytes(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			return
		}
	}
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n <= 0 {
		n = 1024
	}
	w.Header().Set("Content-Length", strconv.Itoa(n))
	w.Header().Set("Content-Type", "application/octet-stream")
	buf := make([]byte, 32<<10)
	for n > 0 {
		k := min(n, len(buf))
		if _, err := w.Write(buf[:k]); err != nil {
			return
		}
		n -= k
	}
}

// serve terminates TLS, reads the VLESS or Trojan request header and joins
// the stream to the origin, whatever destination the header names.
func (l *lab) serve(p *path) {
	for {
		c, err := p.server.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
			var err error
			if p.kind == "vless" {
				err = l.readVLESS(c)
			} else {
				err = l.readTrojan(c)
			}
			if err != nil {
				return
			}
			_ = c.SetReadDeadline(time.Time{})
			if p.kind == "vless" {
				if _, err := c.Write([]byte{0, 0}); err != nil {
					return
				}
			}
			o, err := net.Dial("tcp", l.origin.Addr().String())
			if err != nil {
				return
			}
			defer o.Close()
			join(c, o)
		}()
	}
}

func (l *lab) readVLESS(c net.Conn) error {
	h := make([]byte, 18)
	if _, err := io.ReadFull(c, h); err != nil {
		return err
	}
	if h[0] != 0 || string(h[1:17]) != string(l.uuid[:]) {
		return errors.New("vless: bad header")
	}
	if n := int(h[17]); n > 0 {
		if _, err := io.ReadFull(c, make([]byte, n)); err != nil {
			return err
		}
	}
	cmd := make([]byte, 3) // command, port
	if _, err := io.ReadFull(c, cmd); err != nil {
		return err
	}
	return skipAddr(c, 1, 2, 3)
}

func (l *lab) readTrojan(c net.Conn) error {
	sum := sha256.Sum224([]byte(l.pass))
	h := make([]byte, 56+2+1)
	if _, err := io.ReadFull(c, h); err != nil {
		return err
	}
	if string(h[:56]) != hex.EncodeToString(sum[:]) {
		return errors.New("trojan: bad password")
	}
	if err := skipAddr(c, 1, 3, 4); err != nil {
		return err
	}
	_, err := io.ReadFull(c, make([]byte, 2+2)) // port, CRLF
	return err
}

func skipAddr(r io.Reader, v4, name, v6 byte) error {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return err
	}
	var n int
	switch t[0] {
	case v4:
		n = 4
	case v6:
		n = 16
	case name:
		var b [1]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return err
		}
		n = int(b[0])
	default:
		return errors.New("bad address type")
	}
	_, err := io.ReadFull(r, make([]byte, n))
	return err
}

func join(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}

// reset closes c with an RST instead of a FIN.
func reset(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	c.Close()
}

// relay is the proxy in front of a path: it applies the path's fault, read at
// accept time, to each connection.
func (l *lab) relay(p *path) {
	for {
		c, err := p.proxy.Accept()
		if err != nil {
			return
		}
		p.conns.Add(1)
		f := p.get()
		go l.relayOne(p, c, f)
	}
}

func (l *lab) relayOne(p *path, c net.Conn, f Fault) {
	ep := p.epoch.Load()
	if f == RstLive {
		f = RstHello
	}
	if f == Refuse {
		reset(c)
		return
	}
	if f == Flaky {
		if mrand.Float64() < flakyShare {
			f = RstHello
		} else {
			f = OK
		}
	}
	if f == RstHello {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, _ = c.Read(make([]byte, 4096))
		reset(c)
		return
	}
	if f == Blackhole {
		_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
		io.Copy(io.Discard, c)
		c.Close()
		return
	}
	s, err := net.Dial("tcp", p.server.Addr().String())
	if err != nil {
		reset(c)
		return
	}
	defer s.Close()
	defer c.Close()
	go l.upstream(c, s, f)
	if f == FreezeLive {
		f = Freeze16K
	}

	buf := make([]byte, 16<<10)
	var sent int
	last := time.Time{}
	for {
		k := len(buf)
		if f == Throttle || f == ThrottleRst {
			k = 2 << 10
		}
		n, err := s.Read(buf[:k])
		if n > 0 && f != Freeze16K && p.get() == FreezeLive {
			hold(c) // the path froze under this live connection
			return
		}
		if n > 0 && p.epoch.Load() != ep {
			hold(c) // the network forgot this connection (a NAT entry gone while the phone slept)
			return
		}
		if n > 0 && p.get() == RstLive {
			reset(c) // the path reset this live connection
			return
		}
		if n > 0 {
			switch f {
			case ThrottleRst:
				if sent+n > rstMidBytes {
					reset(c)
					return
				}
				time.Sleep(time.Duration(n) * time.Second / throttleBps)
			case Jitter:
				if mrand.Float64() < jitterShare {
					time.Sleep(time.Duration(mrand.IntN(jitterMs)) * time.Millisecond)
				}
			case RstMid:
				if sent+n > rstMidBytes {
					reset(c)
					return
				}
			case Freeze16K:
				if sent+n > freezeBytes {
					n = freezeBytes - sent
					if n > 0 {
						c.Write(buf[:n])
					}
					hold(c)
					return
				}
			case Throttle:
				time.Sleep(time.Duration(n) * time.Second / throttleBps)
			case Latency:
				// a burst after a pause is an answer to a request: delay it by a round trip
				if time.Since(last) > 100*time.Millisecond {
					time.Sleep(latencyMs * time.Millisecond)
				}
			}
			last = time.Now()
			if _, werr := c.Write(buf[:n]); werr != nil {
				return
			}
			sent += n
		}
		if err != nil {
			return
		}
	}
}

// hold keeps c open and silent downstream, as the TSPU does with a frozen flow.
func hold(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
	io.Copy(io.Discard, c)
}

// upstream carries the client's bytes to the server under the upstream faults.
func (l *lab) upstream(c, s net.Conn, f Fault) {
	defer s.(*net.TCPConn).CloseWrite()
	if f != UpRst && f != UpFreeze {
		io.Copy(s, c)
		return
	}
	buf := make([]byte, 16<<10)
	var sent int
	for {
		n, err := c.Read(buf)
		if n > 0 {
			if f == UpRst && sent+n > upRstBytes {
				reset(c)
				s.Close()
				return
			}
			if f == UpFreeze && sent+n > freezeBytes {
				if k := freezeBytes - sent; k > 0 {
					s.Write(buf[:k])
				}
				// stop reading: nothing more is acknowledged, the client's
				// send buffer fills and its writes block, as when the TSPU
				// drops a frozen flow's packets
				time.Sleep(60 * time.Second)
				return
			}
			if _, werr := s.Write(buf[:n]); werr != nil {
				return
			}
			sent += n
		}
		if err != nil {
			return
		}
	}
}

func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "chaos.test"},
		DNSNames: []string{"chaos.test", "*.chaos.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
