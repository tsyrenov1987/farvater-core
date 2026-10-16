//go:build chaos

package chaos

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"sync"
	"time"

	"crypto/rand"

	"github.com/apernet/hysteria/core/v2/server"
	"golang.org/x/net/http2"

	"github.com/tsyrenov1987/farvater-core/kilvater"
	"github.com/tsyrenov1987/farvater-core/switchboard"
	"github.com/tsyrenov1987/farvater-core/wire"
)

// kilSetup makes the lab's kilvater key and has the core trust the lab's
// certificate: kilvater takes no insecure one.
func (l *lab) kilSetup() error {
	b := make([]byte, 32)
	rand.Read(b)
	l.kilHex = hex.EncodeToString(b)
	k, err := kilvater.ParseKey(l.kilHex)
	if err != nil {
		return err
	}
	l.kilKey = k
	leaf, err := x509.ParseCertificate(l.cert.Certificate[0])
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	wire.SetLabRoots(roots)
	switchboard.SetLabProbe(roots)
	return nil
}

// kilDecoy is the page kilvaterd shows anyone without a key.
func kilDecoy(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte("<!doctype html><title>chaos</title><p>chaos"))
}

// serveKilvater runs kilvater over HTTP/2 on the path's TLS listener; every
// target the clients name is the lab's site.
func (l *lab) serveKilvater(p *path) {
	srv := &kilvater.Server{Verifier: kilvater.NewVerifier([]kilvater.Key{l.kilKey}), Decoy: http.HandlerFunc(kilDecoy),
		AllowPrivate: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, l.origin.Addr().String())
		}}
	for {
		c, err := p.server.Accept()
		if err != nil {
			return
		}
		go func() {
			tc := c.(*tls.Conn)
			_ = tc.SetDeadline(time.Now().Add(15 * time.Second))
			if err := tc.Handshake(); err != nil {
				c.Close()
				return
			}
			_ = tc.SetDeadline(time.Time{})
			(&http2.Server{}).ServeConn(c, &http2.ServeConnOpts{Handler: srv})
		}()
	}
}

type hyAuth struct{ pass string }

func (a hyAuth) Authenticate(_ net.Addr, auth string, _ uint64) (bool, string) {
	return auth == a.pass, "chaos"
}

// hyOut sends every TCP target to the lab's site; UDP is not served.
type hyOut struct{ l *lab }

func (o hyOut) TCP(string) (net.Conn, error) { return net.Dial("tcp", o.l.origin.Addr().String()) }
func (o hyOut) UDP(string) (server.UDPConn, error) {
	return nil, errors.New("chaos: no UDP")
}
func (o hyOut) CheckUDP(string) error { return errors.New("chaos: no UDP") }

// startHy2 runs a Hysteria 2 server and the UDP relay in front of it.
func (l *lab) startHy2(p *path) error {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	p.udpServer = pc
	s, err := server.NewServer(&server.Config{TLSConfig: server.TLSConfig{Certificates: []tls.Certificate{l.cert}},
		Conn: pc, Authenticator: hyAuth{l.pass}, Outbound: hyOut{l}})
	if err != nil {
		return err
	}
	go func() { _ = s.Serve() }()
	if p.udpProxy, err = net.ListenPacket("udp", net.JoinHostPort(p.host, "0")); err != nil {
		return err
	}
	go l.relayUDP(p)
	return nil
}

// udpSess is one client's flow through a UDP relay.
type udpSess struct {
	srv          net.Conn // to the server
	up, down     int      // bytes so far
	dropped      bool     // a Flaky session the path drops whole
	last         time.Time
	mu           sync.Mutex
	client       net.Addr
	throttleNext time.Time
}

// relayUDP is the proxy in front of a Hysteria 2 path. A UDP censor acts on
// packets, so the path's fault applies to every datagram as it passes, on a
// session already running as well: the refusing and resetting faults drop
// everything (QUIC has no RST to send), the cutting ones drop all after their
// byte count, throttle paces the downstream.
func (l *lab) relayUDP(p *path) {
	sess := map[string]*udpSess{}
	var mu sync.Mutex
	buf := make([]byte, 64<<10)
	for {
		n, addr, err := p.udpProxy.ReadFrom(buf)
		if err != nil {
			return
		}
		mu.Lock()
		s := sess[addr.String()]
		if s == nil {
			c, err := net.Dial("udp", p.udpServer.LocalAddr().String())
			if err != nil {
				mu.Unlock()
				continue
			}
			s = &udpSess{srv: c, client: addr, dropped: mrand.Float64() < flakyShare}
			sess[addr.String()] = s
			p.conns.Add(1)
			go l.udpDown(p, s)
		}
		mu.Unlock()
		f := p.get()
		s.mu.Lock()
		drop := false
		switch f {
		case Refuse, RstHello, Blackhole, RstLive:
			drop = true
		case Flaky:
			drop = s.dropped
		case UpRst, UpFreeze:
			drop = s.up+n > upRstBytes
		case RstMid, ThrottleRst:
			drop = s.down > rstMidBytes
		case Freeze16K, FreezeLive:
			drop = s.down > freezeBytes || f == FreezeLive
		}
		if !drop {
			s.up += n
		}
		s.mu.Unlock()
		if !drop {
			s.srv.Write(buf[:n])
		}
	}
}

func (l *lab) udpDown(p *path, s *udpSess) {
	defer s.srv.Close()
	buf := make([]byte, 64<<10)
	for {
		_ = s.srv.SetReadDeadline(time.Now().Add(2 * time.Minute))
		n, err := s.srv.Read(buf)
		if err != nil {
			return
		}
		f := p.get()
		s.mu.Lock()
		drop := false
		switch f {
		case Refuse, RstHello, Blackhole, RstLive:
			drop = true
		case Flaky:
			drop = s.dropped
		case RstMid:
			drop = s.down+n > rstMidBytes
		case ThrottleRst:
			drop = s.down+n > rstMidBytes
		case Freeze16K:
			drop = s.down+n > freezeBytes
		case FreezeLive:
			drop = true
		}
		var wait time.Duration
		if !drop {
			s.down += n
			switch f {
			case Throttle, ThrottleRst:
				// a token bucket: each datagram leaves when the path's rate allows
				now := time.Now()
				if s.throttleNext.Before(now) {
					s.throttleNext = now
				}
				wait = s.throttleNext.Sub(now)
				s.throttleNext = s.throttleNext.Add(time.Duration(n) * time.Second / throttleBps)
			case Latency:
				if time.Since(s.last) > 100*time.Millisecond {
					wait = latencyMs * time.Millisecond
				}
			case Jitter:
				if mrand.Float64() < jitterShare {
					wait = time.Duration(mrand.IntN(jitterMs)) * time.Millisecond
				}
			}
			s.last = time.Now()
		}
		s.mu.Unlock()
		if drop {
			continue
		}
		if wait > 0 {
			pkt := append([]byte(nil), buf[:n]...)
			time.AfterFunc(wait, func() { p.udpProxy.WriteTo(pkt, s.client) })
			continue
		}
		p.udpProxy.WriteTo(buf[:n], s.client)
	}
}
