package kilvater

// Lab checks from the 17.11 low-level audit pass ("проверь непроверенное в
// лаборатории"). Nothing here touches the network beyond loopback.

import (
	"bytes"
	"encoding/base64"
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// deny-dst cannot be sidestepped by spelling a denied IPv4 address as IPv6.
func TestLab17DenyDstAddressSpellings(t *testing.T) {
	s := &Server{
		DenyDst:   []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		SelfPorts: []uint16{443},
		DenyPorts: []uint16{25},
	}
	s.SetDenyExtra([]netip.Prefix{netip.MustParsePrefix("198.51.100.7/32")})
	cases := map[string]bool{
		"203.0.113.5:22":           false, // denied prefix
		"[::ffff:203.0.113.5]:22":  false, // v4-mapped
		"[::203.0.113.5]:22":       false, // v4-compatible (::/96 special)
		"[64:ff9b::cb00:7105]:22":  false, // NAT64 well-known prefix
		"[2002:cb00:7105::1]:22":   false, // 6to4
		"[2001:0:cb00:7105::]:22":  false, // Teredo
		"203.0.113.5:443":          true,  // self-port stays open on purpose
		"198.51.100.7:9100":        false, // reloadable list
		"[::ffff:198.51.100.7]:80": false,
		"1.1.1.1:25":               false, // DenyPorts
		"1.1.1.1:53":               true,
	}
	for a, want := range cases {
		if got := s.allowed(netip.MustParseAddrPort(a)); got != want {
			t.Errorf("%s: allowed=%v, want %v", a, got, want)
		}
	}
	// A zoned address does not parse as AddrPort: the dialer's Control refuses it.
	if err := s.dialer().Control("tcp6", "[fe80::1%lo0]:22", nil); err == nil {
		t.Error("zoned address passed Control")
	}
}

// A connected UDP association only hands back datagrams from its target: a
// third party that learns the node's source port cannot inject into the
// tunnel, and the tunnel is no reflector (each datagram out equals one frame
// in, byte for byte).
func TestLab17UDPOnlyTargetRepliesAndNoAmplification(t *testing.T) {
	target := mustUDPEcho(t)
	seenFrom := make(chan *net.UDPAddr, 1)
	var outBytes int
	go func() {
		b := make([]byte, 64<<10)
		for {
			n, from, err := target.ReadFromUDP(b)
			if err != nil {
				return
			}
			outBytes += n
			select {
			case seenFrom <- from:
			default:
			}
			target.WriteToUDP([]byte("ok"), from)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	upR, upW := io.Pipe()
	downR, downW := io.Pipe()
	done := make(chan struct{})
	go func() {
		(&Server{AllowPrivate: true}).udp(ctx, target.LocalAddr().String(), upR, downW, nil)
		close(done)
	}()
	frames := make(chan []byte, 16)
	go func() {
		for {
			typ, body, err := ReadFrame(downR, nil)
			if err != nil || typ == FrameClose {
				close(frames)
				return
			}
			frames <- append([]byte(nil), body...)
		}
	}()
	payload := bytes.Repeat([]byte("q"), 100)
	WriteFrame(upW, FrameDgram, payload)
	nodePort := <-seenFrom
	if got := <-frames; string(got) != "ok" {
		t.Fatalf("reply %q", got)
	}
	// Third party aims at the node's association port.
	spoof, _ := net.DialUDP("udp", nil, nodePort)
	spoof.Write([]byte("INJECTED"))
	spoof.Close()
	select {
	case f := <-frames:
		t.Fatalf("datagram from a non-target reached the client: %q", f)
	case <-time.After(300 * time.Millisecond):
	}
	if outBytes != len(payload) {
		t.Errorf("node sent %d bytes to the target for %d from the client", outBytes, len(payload))
	}
	cancel()
	upW.Close()
	downR.Close()
	<-done
}

// The labels under one master are prefix-free, and a tag of one version does
// not verify as another.
func TestLab17KDFDomainSeparation(t *testing.T) {
	labels := []string{deriveInfo, kidInfo, nodeInfo, macV2Label, macV3Label, "kilvater/1\x00"}
	for i, a := range labels {
		for j, b := range labels {
			if i != j && strings.HasPrefix(b, a) {
				t.Errorf("label %q is a prefix of %q", a, b)
			}
		}
	}
	var m Key
	for i := range m {
		m[i] = byte(i)
	}
	id := KeyIDFor(m, []byte("sub"))
	k := DeriveKey(m, id)
	if NodeMaster(m, "x") == k {
		t.Error("node master equals derived key")
	}
	now := time.Now()
	v := NewVerifierConfig(VerifierConfig{Master: &m, Authorities: []string{"a.example"}})
	tag2 := NewTagV2(id, k, "/p", now)
	b, _ := decodeTag(tag2)
	b[0] = tagVersion3
	if n, _, _ := v.VerifyDetailHost(encodeTag(b), "a.example", "/p", now); n >= 0 {
		t.Error("v2 tag with its version byte set to 3 verified")
	}
	tag3 := NewTagV3(id, k, "a.example", "/p", now)
	b, _ = decodeTag(tag3)
	b[0] = tagVersion2
	if n, _, _ := v.VerifyDetailHost(encodeTag(b), "a.example", "/p", now); n >= 0 {
		t.Error("v3 tag with its version byte set to 2 verified")
	}
}

// Observation, not a guard: a v3 tag made for another authority verifies when
// the request carries that authority as its Host, even if the node does not
// list it (VerifyDetailHost appends the request's own host to the names).
func TestLab17V3AcceptsRequestHost(t *testing.T) {
	var m Key
	m[0] = 9
	id := KeyIDFor(m, []byte("s"))
	k := DeriveKey(m, id)
	now := time.Now()
	v := NewVerifierConfig(VerifierConfig{Master: &m, Authorities: []string{"mine.example"}})
	tag := NewTagV3(id, k, "other.example", "/p", now)
	n, _, _ := v.VerifyDetailHost(tag, "other.example", "/p", now)
	t.Logf("v3 tag for other.example at node serving mine.example, Host: other.example → verified=%v", n >= 0)
}

func decodeTag(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
func encodeTag(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }
