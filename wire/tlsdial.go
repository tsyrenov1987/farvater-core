package wire

import (
	"context"
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
// keepalive probes after 45 s of quiet.
func dialTCP(ctx context.Context, host string, port int) (net.Conn, error) {
	d := net.Dialer{
		Timeout:         16 * time.Second,
		KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: 45 * time.Second, Interval: 45 * time.Second, Count: -1},
	}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
}

// handshakeTLS runs a TLS client handshake over c that looks like the
// browser the path names. The browser's own ALPN list goes out, except that
// http11 narrows it to http/1.1 (WebSocket, or a link that asks for exactly
// that). The certificate is checked against the server name unless the link
// allows an insecure one.
func handshakeTLS(ctx context.Context, c net.Conn, s PathSpec, http11 bool) (*utls.UConn, error) {
	cfg := &utls.Config{ServerName: s.ServerSNI(), InsecureSkipVerify: s.Insecure, SessionTicketsDisabled: true}
	u := utls.UClient(c, cfg, clientHello(s.Fingerprint))
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
	c, err := dialTCP(ctx, s.Host, s.Port)
	if err != nil {
		return nil, err
	}
	var u *utls.UConn
	if s.Security == "reality" {
		u, err = handshakeREALITY(ctx, c, s)
	} else {
		u, err = handshakeTLS(ctx, c, s, http11)
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	return u, nil
}
