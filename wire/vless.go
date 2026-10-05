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
		var t reflect.Type
		var base unsafe.Pointer
		switch c := iConn.(type) {
		case *tls.Conn:
			if c.ConnectionState().Version != gotls.VersionTLS13 {
				return OutcomeError, errors.New("vision needs TLS 1.3")
			}
			t = reflect.TypeOf(c.Conn).Elem()
			base = unsafe.Pointer(c.Conn)
		case *tls.UConn:
			if c.ConnectionState().Version != utls.VersionTLS13 {
				return OutcomeError, errors.New("vision needs TLS 1.3")
			}
			t = reflect.TypeOf(c.Conn).Elem()
			base = unsafe.Pointer(c.Conn)
		case *reality.UConn:
			t = reflect.TypeOf(c.Conn).Elem()
			base = unsafe.Pointer(c.Conn)
		default:
			return OutcomeError, errors.New("vision needs TLS or REALITY directly")
		}
		i, _ := t.FieldByName("input")
		r, _ := t.FieldByName("rawInput")
		input = (*bytes.Reader)(unsafe.Add(base, i.Offset))
		rawInput = (*bytes.Buffer)(unsafe.Add(base, r.Offset))
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
