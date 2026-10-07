package wire

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	xserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features"
	feature_inbound "github.com/xtls/xray-core/features/inbound"
	feature_outbound "github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/proxy/vmess"
	vmessin "github.com/xtls/xray-core/proxy/vmess/inbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// selfSigned is a certificate for farvater.test, PEM-encoded.
func selfSigned(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "farvater.test"}, DNSNames: []string{"farvater.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
}

// udpEcho answers every datagram with "<its own port>:" and the datagram.
func udpEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	self := c.LocalAddr().(*net.UDPAddr)
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := c.ReadFromUDP(b)
			if err != nil {
				return
			}
			_, _ = c.WriteToUDP(append([]byte(fmt.Sprintf("%d:", self.Port)), b[:n]...), from)
		}
	}()
	return self
}

// testDispatcher stands in for Xray's routing on the server side: Mux.Cool
// goes to Xray's own mux server worker, where XUDP lives, and each UDP or TCP
// destination gets a direct socket, as the freedom outbound would.
type testDispatcher struct{}

func (testDispatcher) Type() interface{} { return routing.DispatcherType() }
func (testDispatcher) Start() error      { return nil }
func (testDispatcher) Close() error      { return nil }

func (d testDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	if dest.Address.String() != "v1.mux.cool" {
		if dest.Network != xnet.Network_TCP {
			return fmt.Errorf("unexpected destination %v", dest)
		}
		c, err := net.Dial("tcp", dest.NetAddr())
		if err != nil {
			return err
		}
		defer c.Close()
		go func() {
			_ = buf.Copy(link.Reader, buf.NewWriter(c))
			_ = c.(*net.TCPConn).CloseWrite()
		}()
		_ = buf.Copy(buf.NewReader(c), link.Writer)
		return nil
	}
	w, err := mux.NewServerWorker(ctx, d, link)
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
	case <-w.WaitClosed():
	}
	return nil
}

func (d testDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	upR, upW := pipe.New()
	downR, downW := pipe.New()
	switch {
	case dest.Address.String() == "v1.mux.cool": // inbounds that dispatch rather than link (VMess)
		if _, err := mux.NewServerWorker(ctx, d, &transport.Link{Reader: upR, Writer: downW}); err != nil {
			return nil, err
		}
	case dest.Network == xnet.Network_TCP:
		c, err := net.Dial("tcp", dest.NetAddr())
		if err != nil {
			return nil, err
		}
		go func() {
			_ = buf.Copy(upR, buf.NewWriter(c))
			_ = c.(*net.TCPConn).CloseWrite()
		}()
		go func() {
			_ = buf.Copy(buf.NewReader(c), downW)
			downW.Close()
			c.Close()
		}()
	case dest.Network == xnet.Network_UDP:
		if err := udpRelay(dest, upR, downW); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unexpected destination %v", dest)
	}
	return &transport.Link{Reader: downR, Writer: upW}, nil
}

// udpRelay sends what comes up to each datagram's address from a socket of
// its own and writes the answers down, marked with where they came from.
func udpRelay(dest xnet.Destination, upR *pipe.Reader, downW *pipe.Writer) error {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	go func() {
		defer c.Close()
		for {
			mb, err := upR.ReadMultiBuffer()
			if err != nil {
				return
			}
			for _, b := range mb {
				to := dest
				if b.UDP != nil {
					to = *b.UDP
				}
				_, _ = c.WriteTo(b.Bytes(), &net.UDPAddr{IP: to.Address.IP(), Port: int(to.Port)})
			}
			buf.ReleaseMulti(mb)
		}
	}()
	go func() {
		p := make([]byte, 2048)
		for {
			n, from, err := c.ReadFromUDP(p)
			if err != nil {
				downW.Close()
				return
			}
			b := buf.New()
			_, _ = b.Write(p[:n])
			src := xnet.UDPDestination(xnet.IPAddress(from.IP), xnet.Port(from.Port))
			b.UDP = &src
			if downW.WriteMultiBuffer(buf.MultiBuffer{b}) != nil {
				return
			}
		}
	}()
	return nil
}

// The VLESS inbound only stores these managers.
type testInbounds struct{ feature_inbound.Manager }
type testOutbounds struct{ feature_outbound.Manager }

func (testInbounds) Type() interface{}  { return feature_inbound.ManagerType() }
func (testOutbounds) Type() interface{} { return feature_outbound.ManagerType() }

// xrayInbound serves Xray's own inbound for cfg over TLS, as farvater.test.
// The whole Xray server cannot be linked here: its outbound manager imports
// sing, which this repository does not link (NOTICE).
func xrayInbound(t *testing.T, cfg interface{}) int {
	t.Helper()
	inst, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []features.Feature{testInbounds{}, testOutbounds{}, testDispatcher{}} {
		if err := inst.AddFeature(f); err != nil {
			t.Fatal(err)
		}
	}
	h, err := core.CreateObject(inst, cfg)
	if err != nil {
		t.Fatal(err)
	}
	handler := h.(proxy.Inbound)
	certPEM, keyPEM := selfSigned(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				tc := xtls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
				defer tc.Close()
				ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "t", Conn: tc})
				_ = handler.Process(ctx, xnet.Network_TCP, tc.(stat.Connection), testDispatcher{})
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// vlessServer is Xray's VLESS inbound for testUUID with the given flow.
func vlessServer(flow string) *vlessin.Config {
	return &vlessin.Config{
		Clients:    []*protocol.User{{Email: "t", Account: xserial.ToTypedMessage(&vless.Account{Id: testUUID, Flow: flow})}},
		Decryption: "none",
	}
}

// xrayVLESS serves VLESS with the given flow.
func xrayVLESS(t *testing.T, flow string) int {
	t.Helper()
	return xrayInbound(t, vlessServer(flow))
}

// xrayTrojan serves Trojan for the password "pw".
func xrayTrojan(t *testing.T) int {
	t.Helper()
	return xrayInbound(t, &trojan.ServerConfig{Users: []*protocol.User{{Email: "t", Account: xserial.ToTypedMessage(&trojan.Account{Password: "pw"})}}})
}

// xrayVMess serves VMess.
func xrayVMess(t *testing.T) int {
	t.Helper()
	return xrayInbound(t, &vmessin.Config{User: []*protocol.User{{Email: "t", Account: xserial.ToTypedMessage(&vmess.Account{Id: testUUID})}}})
}

type hyAuth struct{}

func (hyAuth) Authenticate(_ net.Addr, auth string, _ uint64) (bool, string) {
	return auth == "pw", "t"
}

// hysteriaServer runs a Hysteria 2 server in process.
func hysteriaServer(t *testing.T) int {
	t.Helper()
	certPEM, keyPEM := selfSigned(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s, err := server.NewServer(&server.Config{TLSConfig: server.TLSConfig{Certificates: []tls.Certificate{cert}}, Conn: pc, Authenticator: hyAuth{}})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve() }()
	t.Cleanup(func() { s.Close() })
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// roundTrips sends datagrams to two echoes over one session: each answer must
// come back from its own echo, with the address the path reports.
func roundTrips(t *testing.T, uri string) {
	t.Helper()
	spec, err := ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	w, err := Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ps, err := w.(PacketWire).DialPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()
	e1, e2 := udpEcho(t), udpEcho(t)
	got := make(chan string, 8)
	go func() {
		for {
			p, from, err := ps.ReadPacket()
			if err != nil {
				close(got)
				return
			}
			got <- fmt.Sprintf("%s:%d %s", from.Host, from.Port, p)
		}
	}()
	for i, e := range []*net.UDPAddr{e1, e2, e1} {
		if err := ps.WritePacket([]byte(fmt.Sprintf("dg%d", i)), Target{Host: "127.0.0.1", Port: e.Port}); err != nil {
			t.Fatal(err)
		}
		want := fmt.Sprintf("127.0.0.1:%d %d:dg%d", e.Port, e.Port, i)
		select {
		case g := <-got:
			if g != want {
				t.Fatalf("answer %q, want %q", g, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no answer to datagram %d", i)
		}
	}
}

func TestVLESSUDPOverXUDP(t *testing.T) {
	port := xrayVLESS(t, "")
	roundTrips(t, fmt.Sprintf("vless://%s@127.0.0.1:%d?security=tls&sni=farvater.test&allowInsecure=1&type=tcp#t", testUUID, port))
}

func TestVLESSUDPWithVision(t *testing.T) {
	if raceOn {
		t.Skip("Xray's VLESS inbound does uintptr arithmetic that -race's checkptr rejects; run without -race")
	}
	port := xrayVLESS(t, "xtls-rprx-vision")
	roundTrips(t, fmt.Sprintf("vless://%s@127.0.0.1:%d?security=tls&sni=farvater.test&allowInsecure=1&type=tcp&flow=xtls-rprx-vision#t", testUUID, port))
}

func TestHysteria2UDP(t *testing.T) {
	port := hysteriaServer(t)
	roundTrips(t, fmt.Sprintf("hysteria2://pw@127.0.0.1:%d/?sni=farvater.test&insecure=1#t", port))
}

func TestTrojanUDP(t *testing.T) {
	roundTrips(t, fmt.Sprintf("trojan://pw@127.0.0.1:%d?sni=farvater.test&allowInsecure=1#t", xrayTrojan(t)))
}

func TestVMessUDPOverXUDP(t *testing.T) {
	roundTrips(t, fmt.Sprintf("vmess://%s@127.0.0.1:%d?security=tls&sni=farvater.test&allowInsecure=1&type=tcp#t", testUUID, xrayVMess(t)))
}
