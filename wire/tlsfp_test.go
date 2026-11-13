package wire

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// buildUConn makes the uTLS client uClient would for fp, over a dead pipe, and
// builds its handshake state (no bytes go out). The caller reads the structured
// ClientHello off it.
func buildUConn(t *testing.T, fp string) *utls.UConn {
	t.Helper()
	c, s := net.Pipe()
	t.Cleanup(func() { c.Close(); s.Close() })
	u, err := uClient(c, &utls.Config{ServerName: "example.test"}, fp)
	if err != nil {
		t.Fatalf("uClient(%q): %v", fp, err)
	}
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState(%q): %v", fp, err)
	}
	return u
}

func findTrustAnchors(u *utls.UConn) (*utls.GenericExtension, bool) {
	for _, e := range u.Extensions {
		if g, ok := e.(*utls.GenericExtension); ok && g.Id == extTrustAnchors {
			return g, true
		}
	}
	return nil, false
}

func findSigAlgs(u *utls.UConn) (*utls.SignatureAlgorithmsExtension, bool) {
	for _, e := range u.Extensions {
		if sa, ok := e.(*utls.SignatureAlgorithmsExtension); ok {
			return sa, true
		}
	}
	return nil, false
}

// The auto Chrome request carries the two things a current Chrome adds over the
// Chrome 133 profile uTLS ships: the trust_anchors extension with Chrome's CA
// list, and signature_algorithms led by a GREASE value and the ML-DSA schemes.
// It keeps the TLS 1.3 key share REALITY needs.
func TestChromeAutoTLSProfile(t *testing.T) {
	for _, fp := range []string{"", "chrome", "CHROME"} {
		u := buildUConn(t, fp)

		ta, ok := findTrustAnchors(u)
		if !ok {
			t.Fatalf("fp=%q: no trust_anchors (0xCA34) extension", fp)
		}
		if !bytes.Equal(ta.Data, trustAnchorsBody) {
			t.Errorf("fp=%q: trust_anchors body is %d bytes, want the captured %d", fp, len(ta.Data), len(trustAnchorsBody))
		}

		sa, ok := findSigAlgs(u)
		if !ok {
			t.Fatalf("fp=%q: no signature_algorithms extension", fp)
		}
		if len(sa.SupportedSignatureAlgorithms) < len(chrome154SigAlgLead) {
			t.Fatalf("fp=%q: %d signature algorithms", fp, len(sa.SupportedSignatureAlgorithms))
		}
		lead := sa.SupportedSignatureAlgorithms[:len(chrome154SigAlgLead)]
		for i, want := range chrome154SigAlgLead {
			if lead[i] != want {
				t.Errorf("fp=%q: signature_algorithms[%d] = %#x, want %#x", fp, i, lead[i], want)
			}
		}
		for _, mldsa := range chrome154SigAlgLead[1:] {
			if !containsSigAlg(sa.SupportedSignatureAlgorithms, mldsa) {
				t.Errorf("fp=%q: signature_algorithms missing ML-DSA %#x", fp, mldsa)
			}
		}

		if u.HandshakeState.State13.KeyShareKeys == nil {
			t.Errorf("fp=%q: no TLS 1.3 key share; REALITY would have nothing to derive from", fp)
		}
	}
}

func containsSigAlg(list []utls.SignatureScheme, v utls.SignatureScheme) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// Chrome (BoringSSL) shuffles its extensions but keeps a GREASE extension last,
// and uTLS's HelloChrome_155 does the same. An order-aware DPI that reads the
// raw ClientHello sees a non-GREASE extension in the last slot as "not Chrome",
// so trust_anchors must take part in the shuffle without ever ending up last.
func TestChromeAutoLastExtensionIsGREASE(t *testing.T) {
	for i := 0; i < 300; i++ {
		u := buildUConn(t, "chrome")
		last := u.Extensions[len(u.Extensions)-1]
		if _, ok := last.(*utls.UtlsGREASEExtension); !ok {
			t.Fatalf("try %d: last extension is %T, want GREASE (Chrome keeps GREASE last)", i, last)
		}
	}
}

// An explicit pinned profile is left as uTLS ships it: fp=hellochrome_131 asks
// for exactly Chrome 131, which has no trust_anchors. Only the auto request is
// moved forward to the current Chrome.
func TestExplicitChromeProfileNotUpgraded(t *testing.T) {
	u := buildUConn(t, "hellochrome_131")
	if _, ok := findTrustAnchors(u); ok {
		t.Fatal("fp=hellochrome_131 gained trust_anchors; pinned profiles must be left alone")
	}
}

// The Chrome 154 ClientHello is wire-valid and a server completes a TLS 1.3
// handshake with it: the extra extension and ML-DSA entries do not keep an
// ordinary server from negotiating. ALPN still lands on h2.
func TestChromeAutoTLSHandshake(t *testing.T) {
	cert := selfSignedCert(t, "example.test")
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	srvErr := make(chan error, 1)
	go func() {
		sc := tls.Server(s, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
		if err := sc.HandshakeContext(context.Background()); err != nil {
			srvErr <- err
			return
		}
		srvErr <- nil
		io.Copy(io.Discard, sc) // drain until the client closes
	}()

	u, err := uClient(c, &utls.Config{ServerName: "example.test", InsecureSkipVerify: true}, "chrome")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := u.HandshakeContext(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	st := u.ConnectionState()
	if st.Version != tls.VersionTLS13 {
		t.Errorf("TLS version %#x, want 1.3", st.Version)
	}
	if st.NegotiatedProtocol != "h2" {
		t.Errorf("ALPN %q, want h2", st.NegotiatedProtocol)
	}
	u.Close()
}

// helloShape is what a passive fingerprint reads off a ClientHello, parsed from
// the bytes that go on the wire.
type helloShape struct {
	ciphers, exts, groups, sigalgs, delegCred, certComp, versions []uint16
	keyShares                                                     []uint16 // groups, in order
	keyShareLens                                                  []int
	pskModes                                                      []byte
	recordSizeLimit, echLen                                       int
	hybridReusesX25519                                            bool
}

func be16s(b []byte) []uint16 {
	var r []uint16
	for i := 0; i+1 < len(b); i += 2 {
		r = append(r, uint16(b[i])<<8|uint16(b[i+1]))
	}
	return r
}

// parseHello reads raw, a ClientHello handshake message (4-byte header first).
func parseHello(t *testing.T, raw []byte) helloShape {
	t.Helper()
	var h helloShape
	p := raw[4+2+32:]
	p = p[1+int(p[0]):] // session id
	n := int(p[0])<<8 | int(p[1])
	h.ciphers = be16s(p[2 : 2+n])
	p = p[2+n:]
	p = p[1+int(p[0]):] // compression
	p = p[2:]
	var hybridTail, x25519 []byte
	for len(p) >= 4 {
		typ := uint16(p[0])<<8 | uint16(p[1])
		l := int(p[2])<<8 | int(p[3])
		d := p[4 : 4+l]
		p = p[4+l:]
		h.exts = append(h.exts, typ)
		switch typ {
		case 10:
			h.groups = be16s(d[2:])
		case 13:
			h.sigalgs = be16s(d[2:])
		case 34:
			h.delegCred = be16s(d[2:])
		case 27:
			h.certComp = be16s(d[1:])
		case 43:
			h.versions = be16s(d[1:])
		case 45:
			h.pskModes = append([]byte{}, d[1:]...)
		case 28:
			h.recordSizeLimit = int(d[0])<<8 | int(d[1])
		case 0xfe0d:
			h.echLen = l
		case 51:
			q := d[2:]
			for len(q) >= 4 {
				g := uint16(q[0])<<8 | uint16(q[1])
				kl := int(q[2])<<8 | int(q[3])
				h.keyShares = append(h.keyShares, g)
				h.keyShareLens = append(h.keyShareLens, kl)
				switch g {
				case uint16(utls.X25519MLKEM768):
					hybridTail = q[4+kl-32 : 4+kl]
				case uint16(utls.X25519):
					x25519 = q[4 : 4+kl]
				}
				q = q[4+kl:]
			}
		}
	}
	h.hybridReusesX25519 = hybridTail != nil && bytes.Equal(hybridTail, x25519)
	return h
}

// fp=firefox presents the ClientHello Firefox 160.0 sent on 2026-11-13 (fresh
// profile, first connection), field by field. uTLS's Firefox 148 profile
// differs: no session_ticket or psk_key_exchange_modes, two extra CBC suites,
// two extra FFDHE groups, and a GREASE ECH one byte shorter.
func TestFirefoxAutoMatchesFirefox160(t *testing.T) {
	eq := func(name string, got, want any) {
		t.Helper()
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	for i := 0; i < 20; i++ {
		u := buildUConn(t, "firefox")
		h := parseHello(t, u.HandshakeState.Hello.Raw)
		eq("ciphers", h.ciphers, []uint16{0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc013, 0xc014, 0x9c, 0x9d, 0x2f, 0x35})
		eq("extension order", h.exts, []uint16{0, 23, 65281, 10, 11, 35, 16, 5, 34, 18, 51, 43, 13, 45, 28, 27, 0xfe0d})
		eq("groups", h.groups, []uint16{0x11ec, 0x1d, 0x17, 0x18, 0x19})
		eq("key share groups", h.keyShares, []uint16{0x11ec, 0x1d, 0x17})
		eq("key share lengths", h.keyShareLens, []int{1216, 32, 65})
		eq("signature_algorithms", h.sigalgs, []uint16{0x403, 0x503, 0x603, 0x804, 0x805, 0x806, 0x401, 0x501, 0x601, 0x203, 0x201})
		eq("delegated_credentials", h.delegCred, []uint16{0x403, 0x503, 0x603, 0x203})
		eq("compress_certificate", h.certComp, []uint16{1, 2, 3})
		eq("supported_versions", h.versions, []uint16{0x304, 0x303})
		eq("psk_key_exchange_modes", h.pskModes, []byte{1})
		eq("record_size_limit", h.recordSizeLimit, 0x4001)
		eq("GREASE ECH length", h.echLen, 282)
		if !h.hybridReusesX25519 {
			t.Error("the X25519 share is not the one inside X25519MLKEM768; Firefox (NSS) reuses it")
		}
		if t.Failed() {
			return
		}
	}
}

// The Firefox ClientHello completes a TLS 1.3 handshake whichever key share the
// server picks: the hybrid one (Go's default) or plain X25519. The reused X25519
// key must work in both.
func TestFirefoxAutoTLSHandshake(t *testing.T) {
	for _, curves := range [][]tls.CurveID{nil, {tls.X25519}} {
		cert := selfSignedCert(t, "example.test")
		c, s := net.Pipe()
		srvErr := make(chan error, 1)
		go func() {
			sc := tls.Server(s, &tls.Config{Certificates: []tls.Certificate{cert}, CurvePreferences: curves, NextProtos: []string{"h2"}})
			srvErr <- sc.HandshakeContext(context.Background())
			io.Copy(io.Discard, sc)
		}()
		u, err := uClient(c, &utls.Config{ServerName: "example.test", InsecureSkipVerify: true}, "firefox")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := u.HandshakeContext(ctx); err != nil {
			t.Fatalf("curves %v: client handshake: %v", curves, err)
		}
		cancel()
		if err := <-srvErr; err != nil {
			t.Fatalf("curves %v: server handshake: %v", curves, err)
		}
		if st := u.ConnectionState(); st.Version != tls.VersionTLS13 || st.NegotiatedProtocol != "h2" {
			t.Errorf("curves %v: version %#x ALPN %q", curves, st.Version, st.NegotiatedProtocol)
		}
		u.Close()
		c.Close()
		s.Close()
	}
}
