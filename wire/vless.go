package wire

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"errors"
	"io"
	"reflect"
	"time"
	"unsafe"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/xudp"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// IdleTimeout closes a flow with no traffic in either direction.
var IdleTimeout = 5 * time.Minute

type vlessWire struct {
	spec PathSpec
	dest xnet.Destination
	mss  *internet.MemoryStreamConfig
	user *protocol.MemoryUser
	acc  *vless.MemoryAccount
}

func newVLESS(spec PathSpec) (*vlessWire, error) {
	mss, err := buildStream(spec)
	if err != nil {
		return nil, err
	}
	if spec.Flow == vless.XRV && spec.Network != "tcp" {
		return nil, errors.New("xtls-rprx-vision needs a raw TCP transport")
	}
	acc, err := (&vless.Account{Id: spec.UUID, Flow: spec.Flow, Encryption: "none"}).AsAccount()
	if err != nil {
		return nil, err
	}
	mem := acc.(*vless.MemoryAccount)
	return &vlessWire{
		spec: spec,
		dest: xnet.TCPDestination(xnet.ParseAddress(spec.Host), xnet.Port(spec.Port)),
		mss:  mss,
		user: &protocol.MemoryUser{Account: mem, Email: spec.ID},
		acc:  mem,
	}, nil
}

func (w *vlessWire) ID() string           { return w.spec.ID }
func (w *vlessWire) Spec() PathSpec       { return w.spec }
func (w *vlessWire) NeedsHandshake() bool { return true }
func (w *vlessWire) Close() error         { return nil }

// Dial establishes the outer transport (TCP + TLS/REALITY, WebSocket upgrade or
// the XHTTP session). Nothing about the target is sent yet.
func (w *vlessWire) Dial(ctx context.Context) (Session, error) {
	ob := &session.Outbound{Name: "vless"}
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{ob})
	conn, err := internet.Dial(ctx, w.dest, w.mss)
	if err != nil {
		return nil, err
	}
	return &vlessSession{w: w, conn: conn, ob: ob}, nil
}

type vlessSession struct {
	w    *vlessWire
	conn stat.Connection
	ob   *session.Outbound
}

func (s *vlessSession) Close() error { return s.conn.Close() }

func (s *vlessSession) Run(ctx context.Context, target Target, prelude []byte, up <-chan []byte, down io.Writer, m Meter) (Outcome, error) {
	conn := s.conn
	defer conn.Close()
	iConn := stat.TryUnwrapStatsConn(conn)

	s.ob.Target = xnet.TCPDestination(xnet.ParseAddress(target.Host), xnet.Port(target.Port))
	s.ob.Conn = conn
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{s.ob})

	request := &protocol.RequestHeader{
		Version: encoding.Version,
		User:    s.w.user,
		Command: protocol.RequestCommandTCP,
		Address: s.ob.Target.Address,
		Port:    s.ob.Target.Port,
	}
	addons := &encoding.Addons{Flow: s.w.acc.Flow}

	var input *bytes.Reader
	var rawInput *bytes.Buffer
	if addons.Flow == vless.XRV {
		s.ob.CanSpliceCopy = 2
		var err error
		if input, rawInput, err = visionBuffers(iConn); err != nil {
			return OutcomeError, err
		}
	} else {
		s.ob.CanSpliceCopy = 3
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, IdleTimeout)
	go func() {
		<-ctx.Done()
		conn.Close() // unblocks the downstream reader
	}()
	ts := proxy.NewTrafficState(s.w.acc.ID.Bytes())

	bw := buf.NewBufferedWriter(buf.NewWriter(conn))
	if err := encoding.EncodeRequestHeader(bw, request, addons); err != nil {
		return OutcomeError, err
	}
	serverWriter := encoding.EncodeBodyAddons(bw, request, addons, ts, true, ctx, conn, s.ob)
	if len(prelude) > 0 {
		if err := serverWriter.WriteMultiBuffer(buf.MergeBytes(nil, prelude)); err != nil {
			return OutcomeError, err
		}
	} else if addons.Flow == vless.XRV {
		if err := serverWriter.WriteMultiBuffer(make(buf.MultiBuffer, 1)); err != nil {
			return OutcomeError, err
		}
	}
	if err := bw.SetBuffered(false); err != nil {
		return OutcomeError, err
	}

	upErr := make(chan error, 1)
	go func() { upErr <- pumpUp(ctx, up, serverWriter, m, timer) }()
	downErr := make(chan error, 1)
	go func() {
		responseAddons, err := encoding.DecodeResponseHeader(conn, request)
		if err != nil {
			downErr <- err
			return
		}
		serverReader := encoding.DecodeBodyAddons(conn, request, responseAddons)
		dw := &downWriter{w: down, m: m}
		if addons.Flow == vless.XRV {
			serverReader = proxy.NewVisionReader(serverReader, ts, false, ctx, conn, input, rawInput, s.ob)
			downErr <- encoding.XtlsRead(serverReader, dw, timer, conn, ts, false, ctx)
			return
		}
		downErr <- buf.Copy(serverReader, dw, buf.UpdateActivity(timer))
	}()
	return settle(ctx, upErr, downErr, cancel, timer, func() { timer.SetTimeout(2 * time.Second) })
}

// visionBuffers reaches the TLS connection's input and rawInput, which Vision
// drains when it switches to direct copy.
func visionBuffers(iConn stat.Connection) (*bytes.Reader, *bytes.Buffer, error) {
	var t reflect.Type
	var base unsafe.Pointer
	switch c := iConn.(type) {
	case *tls.Conn:
		if c.ConnectionState().Version != gotls.VersionTLS13 {
			return nil, nil, errors.New("vision needs TLS 1.3")
		}
		t = reflect.TypeOf(c.Conn).Elem()
		base = unsafe.Pointer(c.Conn)
	case *tls.UConn:
		if c.ConnectionState().Version != utls.VersionTLS13 {
			return nil, nil, errors.New("vision needs TLS 1.3")
		}
		t = reflect.TypeOf(c.Conn).Elem()
		base = unsafe.Pointer(c.Conn)
	case *reality.UConn:
		t = reflect.TypeOf(c.Conn).Elem()
		base = unsafe.Pointer(c.Conn)
	default:
		return nil, nil, errors.New("vision needs TLS or REALITY directly")
	}
	i, _ := t.FieldByName("input")
	r, _ := t.FieldByName("rawInput")
	return (*bytes.Reader)(unsafe.Add(base, i.Offset)), (*bytes.Buffer)(unsafe.Add(base, r.Offset)), nil
}

// DialPacket establishes the outer transport for a UDP association. Datagrams
// travel as XUDP (Mux.Cool to v1.mux.cool:666), as Xray's own client sends
// them: the framing Vision requires, naming each datagram's address.
func (w *vlessWire) DialPacket(ctx context.Context) (PacketSession, error) {
	ob := &session.Outbound{Name: "vless"}
	conn, err := internet.Dial(session.ContextWithOutbounds(ctx, []*session.Outbound{ob}), w.dest, w.mss)
	if err != nil {
		return nil, err
	}
	s := &vlessPacketSession{
		conn:    conn,
		ob:      ob,
		addons:  &encoding.Addons{Flow: w.acc.Flow},
		ts:      proxy.NewTrafficState(w.acc.ID.Bytes()),
		request: &protocol.RequestHeader{Version: encoding.Version, User: w.user, Command: protocol.RequestCommandMux, Address: xnet.DomainAddress("v1.mux.cool"), Port: 666},
	}
	if s.addons.Flow == vless.XRV {
		ob.CanSpliceCopy = 2
		if s.input, s.rawInput, err = visionBuffers(stat.TryUnwrapStatsConn(conn)); err != nil {
			conn.Close()
			return nil, err
		}
	} else {
		ob.CanSpliceCopy = 3
	}
	s.ctx, s.cancel = context.WithCancel(session.ContextWithOutbounds(context.Background(), []*session.Outbound{ob}))
	return s, nil
}

type vlessPacketSession struct {
	conn     stat.Connection
	ob       *session.Outbound
	addons   *encoding.Addons
	ts       *proxy.TrafficState
	request  *protocol.RequestHeader
	input    *bytes.Reader
	rawInput *bytes.Buffer
	ctx      context.Context
	cancel   context.CancelFunc

	w    buf.Writer // set by the first WritePacket, which sends the request
	r    buf.Reader // set by the first ReadPacket, which reads the response header
	pend buf.MultiBuffer
}

func (s *vlessPacketSession) Close() error {
	s.cancel()
	return s.conn.Close()
}

func udpDest(t Target) xnet.Destination {
	return xnet.UDPDestination(xnet.ParseAddress(t.Host), xnet.Port(t.Port))
}

func (s *vlessPacketSession) WritePacket(p []byte, target Target) error {
	dest := udpDest(target)
	b := buf.New()
	if _, err := b.Write(p); err != nil {
		b.Release()
		return err // larger than a buffer: XUDP could not carry it either
	}
	b.UDP = &dest
	if s.w != nil {
		return s.w.WriteMultiBuffer(buf.MultiBuffer{b})
	}
	s.ob.Target = dest
	bw := buf.NewBufferedWriter(buf.NewWriter(s.conn))
	if err := encoding.EncodeRequestHeader(bw, s.request, s.addons); err != nil {
		b.Release()
		return err
	}
	w := xudp.NewPacketWriter(encoding.EncodeBodyAddons(bw, s.request, s.addons, s.ts, true, s.ctx, s.conn, s.ob), dest, [8]byte{})
	if err := w.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		return err
	}
	if err := bw.SetBuffered(false); err != nil {
		return err
	}
	s.w = w
	return nil
}

func (s *vlessPacketSession) ReadPacket() ([]byte, Target, error) {
	if s.r == nil {
		responseAddons, err := encoding.DecodeResponseHeader(s.conn, s.request)
		if err != nil {
			return nil, Target{}, err
		}
		if s.addons.Flow == vless.XRV {
			vr := proxy.NewVisionReader(encoding.DecodeBodyAddons(s.conn, s.request, responseAddons), s.ts, false, s.ctx, s.conn, s.input, s.rawInput, s.ob)
			s.r = xudp.NewPacketReader(&buf.BufferedReader{Reader: vr})
		} else {
			s.r = xudp.NewPacketReader(s.conn)
		}
	}
	return nextPacket(s.r, &s.pend)
}
