package wire

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	goreality "github.com/xtls/reality"
	xnet "github.com/xtls/xray-core/common/net"
	xserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/internet"
	xgrpc "github.com/xtls/xray-core/transport/internet/grpc"
	xreality "github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tcp"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/websocket"
	"google.golang.org/protobuf/proto"
)

// xrayInstance is an Xray core with the stand-ins the inbounds need.
func xrayInstance(t *testing.T) *core.Instance {
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
	return inst
}

// xrayServe serves Xray's own inbound for cfg behind Xray's own transport
// listener for sc: the server half of every transport this core speaks.
func xrayServe(t *testing.T, cfg interface{}, sc *internet.StreamConfig) int {
	t.Helper()
	h, err := core.CreateObject(xrayInstance(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	handler := h.(proxy.Inbound)
	mss, err := internet.ToMemoryStreamConfig(sc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// Xray reads port 0 as a Unix socket: take a free port first.
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	ln, err := internet.ListenTCP(ctx, xnet.LocalHostIP, xnet.Port(port), mss, func(c stat.Connection) {
		go func() {
			defer c.Close()
			ictx := session.ContextWithInbound(ctx, &session.Inbound{Tag: "t", Conn: c})
			if err := handler.Process(ictx, xnet.Network_TCP, c, testDispatcher{}); err != nil {
				t.Logf("server: %v", err)
			}
		}()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	// gRPC binds in a background goroutine with no readiness signal; wait
	// until the port accepts before handing it to the client.
	for i := 0; i < 200; i++ {
		c, derr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if derr == nil {
			c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return port
}

// tlsDest is the site a REALITY server answers for: a plain TLS 1.3 server
// for farvater.test.
func tlsDest(t *testing.T) int {
	t.Helper()
	certPEM, keyPEM := selfSigned(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}})
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
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// testREALITY is a REALITY server's settings and what its links carry.
type testREALITY struct {
	server  *xreality.Config
	pbk     string // the public key, as links write it
	sid     string
	privKey []byte
}

func newREALITY(t *testing.T) testREALITY {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sid := []byte{0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71}
	dest := fmt.Sprintf("127.0.0.1:%d", tlsDest(t))
	// A REALITY server copies the post-handshake records its dest sends, which
	// it learns in the background; until it knows them, every handshake waits
	// in 5 s steps. The test dest sends none: say so up front.
	for alpn := range 3 {
		goreality.GlobalPostHandshakeRecordsLens.Store(fmt.Sprintf("%s farvater.test %d", dest, alpn), []int{})
	}
	return testREALITY{
		server: &xreality.Config{Dest: dest, Type: "tcp", ServerNames: []string{"farvater.test"},
			PrivateKey: key.Bytes(), ShortIds: [][]byte{sid}},
		pbk:     base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
		sid:     hex.EncodeToString(sid),
		privKey: key.Bytes(),
	}
}

// serverTLS is Xray's TLS on the server side, as farvater.test.
func serverTLS(t *testing.T) *xtls.Config {
	t.Helper()
	certPEM, keyPEM := selfSigned(t)
	return &xtls.Config{Certificate: []*xtls.Certificate{{Certificate: certPEM, Key: keyPEM}}}
}

// serverStream is the server's transport for network ("tcp", "ws", "grpc",
// "xhttp") under security (an Xray TLS or REALITY config).
func serverStream(network string, security proto.Message) *internet.StreamConfig {
	sc := &internet.StreamConfig{}
	var settings proto.Message
	switch network {
	case "tcp":
		sc.ProtocolName, settings = "tcp", &tcp.Config{}
	case "ws":
		sc.ProtocolName, settings = "websocket", &websocket.Config{Path: "/ws"}
	case "grpc":
		sc.ProtocolName, settings = "grpc", &xgrpc.Config{ServiceName: "svc"}
	case "xhttp":
		sc.ProtocolName, settings = "splithttp", &splithttp.Config{Path: "/xh"}
	}
	sc.TransportSettings = []*internet.TransportConfig{{ProtocolName: sc.ProtocolName, Settings: xserial.ToTypedMessage(settings)}}
	sc.SecurityType = xserial.GetMessageType(security)
	sc.SecuritySettings = []*xserial.TypedMessage{xserial.ToTypedMessage(security)}
	return sc
}

// linkQuery is the part of a share link that names the transport and its
// security, matching serverStream.
func linkQuery(network, mode string, r *testREALITY) string {
	q := "type=" + network
	switch network {
	case "ws":
		q += "&path=%2Fws"
	case "grpc":
		q += "&serviceName=svc"
	case "xhttp":
		q += "&path=%2Fxh"
	}
	if mode != "" {
		q += "&mode=" + mode
	}
	if r != nil {
		return q + "&security=reality&sni=farvater.test&fp=firefox&pbk=" + r.pbk + "&sid=" + r.sid
	}
	return q + "&security=tls&sni=farvater.test&allowInsecure=1"
}

// echoOver carries one flow over an established session to a TCP echo.
func echoOver(t *testing.T, ctx context.Context, sess Session) {
	t.Helper()
	port := echoTCP(t)
	up := make(chan []byte, 1)
	pr, pw := io.Pipe()
	ended := make(chan Outcome, 1)
	go func() {
		o, _ := sess.Run(ctx, Target{Host: "127.0.0.1", Port: port}, []byte("hello "), up, pw, nopMeter{})
		pw.Close()
		ended <- o
	}()
	for i, want := range []string{"hello ", "world"} {
		if i > 0 {
			up <- []byte(want)
		}
		got := make([]byte, len(want))
		if _, err := io.ReadFull(pr, got); err != nil || string(got) != want {
			t.Fatalf("echo %q (%v), want %q", got, err, want)
		}
	}
	close(up)
	go func() { _, _ = io.Copy(io.Discard, pr) }()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the flow did not end")
	}
}

// The switchboard ends the dial's context as soon as Dial returns: the
// session it got must still carry the flow, on every transport.
func TestSessionOutlivesDialContext(t *testing.T) {
	if raceOn {
		t.Skip("Xray's inbounds do uintptr arithmetic that -race's checkptr rejects")
	}
	for _, network := range []string{"tcp", "ws", "grpc", "xhttp"} {
		for _, sec := range []string{"tls", "reality"} {
			if network == "ws" && sec == "reality" {
				continue // Xray does not serve WebSocket under REALITY
			}
			t.Run(network+"+"+sec, func(t *testing.T) {
				var security proto.Message = serverTLS(t)
				var r *testREALITY
				if sec == "reality" {
					rr := newREALITY(t)
					r, security = &rr, rr.server
				}
				port := xrayServe(t, vlessServer(""), serverStream(network, security))
				spec, err := ParseURI(fmt.Sprintf("vless://%s@127.0.0.1:%d?%s#t", testUUID, port, linkQuery(network, "", r)))
				if err != nil {
					t.Fatal(err)
				}
				w, err := Build(spec)
				if err != nil {
					t.Fatal(err)
				}
				defer w.Close()
				dctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				sess, err := w.Dial(dctx)
				cancel()
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancelRun := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancelRun()
				echoOver(t, ctx, sess)
			})
		}
	}
}
