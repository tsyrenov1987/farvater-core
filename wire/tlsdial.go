package wire

import (
	"context"
	"crypto/x509"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// fingerprints names the browser ClientHellos a link can ask for (its fp
// parameter), as share links spell them.
var fingerprints = map[string]*utls.ClientHelloID{
	"chrome":  &utls.HelloChrome_Auto,
	"firefox": &utls.HelloFirefox_Auto,
	"safari":  &utls.HelloSafari_Auto,
	"ios":     &utls.HelloIOS_Auto,
	"android": &utls.HelloAndroid_11_OkHttp,
	"edge":    &utls.HelloEdge_Auto,
	"360":     &utls.Hello360_Auto,
	"qq":      &utls.HelloQQ_Auto,

	"hellochrome_120":  &utls.HelloChrome_120,
	"hellochrome_131":  &utls.HelloChrome_131,
	"hellofirefox_120": &utls.HelloFirefox_120,
	"helloios_14":      &utls.HelloIOS_14,
	"hellosafari_16_0": &utls.HelloSafari_16_0,
	"helloedge_106":    &utls.HelloEdge_106,
}

// randomPool is what fp=random picks from, once per process.
var randomPool = []*utls.ClientHelloID{
	&utls.HelloChrome_120, &utls.HelloChrome_131, &utls.HelloFirefox_120, &utls.HelloIOS_14,
	&utls.HelloSafari_16_0, &utls.HelloEdge_106,
}

var (
	randomOnce            sync.Once
	randomHello           utls.ClientHelloID
	randomizedHello       utls.ClientHelloID
	randomizedNoALPNHello utls.ClientHelloID
)

func pickRandomHellos() {
	randomHello = *randomPool[rand.IntN(len(randomPool))]
	w := utls.DefaultWeights
	w.TLSVersMax_Set_VersionTLS13 = 1 // REALITY and Vision need TLS 1.3
	w.FirstKeyShare_Set_CurveP256 = 0
	for _, h := range []struct {
		dst  *utls.ClientHelloID
		base utls.ClientHelloID
	}{{&randomizedHello, utls.HelloRandomizedALPN}, {&randomizedNoALPNHello, utls.HelloRandomizedNoALPN}} {
		seed, err := utls.NewPRNGSeed()
		if err != nil {
			*h.dst = utls.HelloChrome_Auto
			continue
		}
		id := h.base
		id.Seed = seed
		id.Weights = &w
		*h.dst = id
	}
}

// clientHello is the ClientHello for a link's fp parameter: Chrome's when it
// names none or one this core does not know.
func clientHello(fp string) utls.ClientHelloID {
	switch fp = strings.ToLower(fp); fp {
	case "random", "randomized", "randomizednoalpn":
		randomOnce.Do(pickRandomHellos)
		switch fp {
		case "random":
			return randomHello
		case "randomized":
			return randomizedHello
		}
		return randomizedNoALPNHello
	}
	if id := fingerprints[fp]; id != nil {
		return *id
	}
	return utls.HelloChrome_Auto
}

// dialTCP connects with a browser's socket defaults: 16 s to connect,
// keepalive probes after 45 s of quiet. A server given by name is asked of
// DNS once: the address that connected is kept (addrs) and dialled straight
// the next time, as a browser's host cache spares a lookup a connection.
func dialTCP(ctx context.Context, host string, port int) (net.Conn, error) {
	d := net.Dialer{
		Control:         SocketControl,
		Timeout:         16 * time.Second,
		KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: 45 * time.Second, Interval: 45 * time.Second, Count: -1},
	}
	p := strconv.Itoa(port)
	named := net.ParseIP(host) == nil
	if named {
		if ip := addrs.get(host); ip != "" {
			// Bounded, so an address gone dead leaves time to ask DNS again.
			kctx, cancel := context.WithTimeout(ctx, addrKeptDial)
			c, err := d.DialContext(kctx, "tcp", net.JoinHostPort(ip, p))
			cancel()
			if err == nil {
				return &recordConn{Conn: c}, nil
			}
			addrs.drop(host, ip)
			if ctx.Err() != nil {
				return nil, err
			}
		}
	}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, p))
	if err != nil {
		return nil, err
	}
	if named {
		if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
			addrs.put(host, a.IP.String())
		}
	}
	return &recordConn{Conn: c}, nil
}

// addrKept: how long the address a name last connected at is dialled without
// asking DNS. addrKeptDial bounds a connect to it.
const (
	addrKept     = 5 * time.Minute
	addrKeptDial = 3 * time.Second
)

// addrCache keeps, per server name, the address that last connected.
type addrCache struct {
	mu  sync.Mutex
	m   map[string]keptAddr
	now func() time.Time
}

type keptAddr struct {
	ip string
	at time.Time
}

var addrs = &addrCache{m: map[string]keptAddr{}, now: time.Now}

func (a *addrCache) get(host string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	k, ok := a.m[host]
	if !ok || a.now().Sub(k.at) >= addrKept {
		delete(a.m, host)
		return ""
	}
	return k.ip
}

// put keeps ip for host; an address already kept keeps its age, so every
// name is asked of DNS again once in addrKept.
func (a *addrCache) put(host, ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if k, ok := a.m[host]; !ok || k.ip != ip {
		a.m[host] = keptAddr{ip, a.now()}
	}
}

func (a *addrCache) drop(host, ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.m[host].ip == ip {
		delete(a.m, host)
	}
}

// ForgetAddrs drops the kept server addresses: on a new network a name may
// answer with other ones.
func ForgetAddrs() {
	addrs.mu.Lock()
	defer addrs.mu.Unlock()
	clear(addrs.m)
}

// handshakeTLS runs a TLS client handshake over c that looks like the
// browser the path names. The browser's own ALPN list goes out, except that
// http11 narrows it to http/1.1 (WebSocket, or a link that asks for exactly
// that). The certificate is checked against the server name unless the link
// allows an insecure one.
// labRoots, when set (only by the chaos lab's build, roots_chaos.go), are
// the roots path certificates are verified against instead of the system's.
var labRoots *x509.CertPool

// tlsSessions keeps the sessions servers give the core's TLS connections
// (paths with real TLS and BrowserTransport; REALITY never stores one), so
// the next connection to the same name resumes with a pre_shared_key as a
// browser coming back to a site does. Every connection a full handshake is
// not what a browser does.
var tlsSessions = utls.NewLRUClientSessionCache(256)

func handshakeTLS(ctx context.Context, c net.Conn, s PathSpec, http11 bool) (*utls.UConn, error) {
	cfg := &utls.Config{ServerName: s.ServerSNI(), InsecureSkipVerify: s.Insecure, ClientSessionCache: tlsSessions, RootCAs: labRoots}
	u, err := uClient(c, cfg, s.Fingerprint)
	if err != nil {
		return nil, err
	}
	if http11 {
		if err := u.BuildHandshakeState(); err != nil {
			return nil, err
		}
		set := false
		for _, e := range u.Extensions {
			if a, ok := e.(*utls.ALPNExtension); ok {
				a.AlpnProtocols, set = []string{"http/1.1"}, true
				break
			}
		}
		if !set {
			u.Extensions = append(u.Extensions, &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}})
		}
		if err := u.BuildHandshakeState(); err != nil {
			return nil, err
		}
	}
	if err := u.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return u, nil
}

// dialSecure connects to the path's server and runs its TLS or REALITY
// handshake.
func dialSecure(ctx context.Context, s PathSpec, http11 bool) (*utls.UConn, error) {
	return dialSecureVia(ctx, handshakes, s, http11, false)
}

// dialSecurePaced is dialSecure for a wire that keeps one connection for all
// its flows: the handshake waits its turn among those to the same server
// name, or is refused with ErrHandshakePaced (hsgate.go).
func dialSecurePaced(ctx context.Context, s PathSpec, http11 bool) (*utls.UConn, error) {
	return dialSecureVia(ctx, handshakes, s, http11, true)
}

func dialSecureVia(ctx context.Context, g *hsGate, s PathSpec, http11, paced bool) (*utls.UConn, error) {
	name := s.ServerSNI()
	var slot time.Time
	var err error
	if paced {
		if slot, err = g.reserve(ctx, name, s.Fingerprint); err != nil {
			return nil, err
		}
	}
	var c net.Conn
	if s.TURN != nil {
		c, err = dialTURN(ctx, s)
	} else {
		c, err = dialTCP(ctx, s.Host, s.Port)
	}
	if err != nil {
		if paced {
			g.cancel(name, slot) // no ClientHello went out
		}
		return nil, err
	}
	gap := g.begin(name)
	var u *utls.UConn
	if s.Security == "reality" {
		u, err = handshakeREALITY(ctx, c, s)
	} else {
		u, err = handshakeTLS(ctx, c, s, http11)
	}
	g.done(ctx, s.ID, name, s.Fingerprint, gap, s.TURN != nil, err)
	if err != nil {
		c.Close()
		return nil, err
	}
	return u, nil
}
