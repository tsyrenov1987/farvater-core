package wire

import (
	"bytes"
	"context"
	"crypto/tls"
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
