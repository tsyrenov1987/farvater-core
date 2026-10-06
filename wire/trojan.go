package wire

import (
	"context"
	"io"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type trojanWire struct {
	spec PathSpec
	dest xnet.Destination
	mss  *internet.MemoryStreamConfig
	acc  *trojan.MemoryAccount
}

func newTrojan(spec PathSpec) (*trojanWire, error) {
	mss, err := buildStream(spec)
	if err != nil {
		return nil, err
	}
	acc, err := (&trojan.Account{Password: spec.Password}).AsAccount()
	if err != nil {
		return nil, err
	}
	return &trojanWire{
		spec: spec,
		dest: xnet.TCPDestination(xnet.ParseAddress(spec.Host), xnet.Port(spec.Port)),
		mss:  mss,
		acc:  acc.(*trojan.MemoryAccount),
	}, nil
}

func (w *trojanWire) ID() string           { return w.spec.ID }
func (w *trojanWire) Spec() PathSpec       { return w.spec }
func (w *trojanWire) NeedsHandshake() bool { return true }
func (w *trojanWire) Close() error         { return nil }

// Dial establishes the outer transport. Nothing about the target is sent yet.
func (w *trojanWire) Dial(ctx context.Context) (Session, error) {
	conn, err := dialStream(ctx, "trojan", w.dest, w.mss)
	if err != nil {
		return nil, err
	}
	return &trojanSession{w: w, conn: conn}, nil
}

type trojanSession struct {
	w    *trojanWire
	conn stat.Connection
}

func (s *trojanSession) Close() error { return s.conn.Close() }

func (s *trojanSession) Run(ctx context.Context, target Target, prelude []byte, up <-chan []byte, down io.Writer, m Meter) (Outcome, error) {
	conn := s.conn
	defer conn.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, IdleTimeout)
	go func() {
		<-ctx.Done()
		conn.Close() // unblocks the downstream reader
	}()

	// The request header and the first payload leave in one write: the server
	// reads the header from its first read.
	bw := buf.NewBufferedWriter(buf.NewWriter(conn))
	cw := &trojan.ConnWriter{Writer: bw, Target: xnet.TCPDestination(xnet.ParseAddress(target.Host), xnet.Port(target.Port)), Account: s.w.acc}
	if _, err := cw.Write(prelude); err != nil {
		return OutcomeError, err
	}
	if err := bw.SetBuffered(false); err != nil {
		return OutcomeError, err
	}

	upErr := make(chan error, 1)
	go func() { upErr <- pumpUp(ctx, up, cw, m, timer) }()
	downErr := make(chan error, 1)
	go func() {
		downErr <- buf.Copy(buf.NewReader(conn), &downWriter{w: down, m: m}, buf.UpdateActivity(timer))
	}()
	return settle(ctx, upErr, downErr, cancel, timer, func() { timer.SetTimeout(2 * time.Second) })
}

// DialPacket establishes the outer transport for a UDP association. Trojan
// frames each datagram with its own address.
func (w *trojanWire) DialPacket(ctx context.Context) (PacketSession, error) {
	conn, err := dialStream(ctx, "trojan", w.dest, w.mss)
	if err != nil {
		return nil, err
	}
	return &trojanPacketSession{conn: conn, acc: w.acc}, nil
}

type trojanPacketSession struct {
	conn stat.Connection
	acc  *trojan.MemoryAccount

	w    buf.Writer // set by the first WritePacket, which sends the request
	r    buf.Reader
	pend buf.MultiBuffer
}

func (s *trojanPacketSession) Close() error { return s.conn.Close() }

func (s *trojanPacketSession) WritePacket(p []byte, target Target) error {
	dest := udpDest(target)
	b := buf.New()
	if _, err := b.Write(p); err != nil {
		b.Release()
		return err
	}
	b.UDP = &dest
	if s.w != nil {
		return s.w.WriteMultiBuffer(buf.MultiBuffer{b})
	}
	bw := buf.NewBufferedWriter(buf.NewWriter(s.conn))
	w := &trojan.PacketWriter{Writer: &trojan.ConnWriter{Writer: bw, Target: dest, Account: s.acc}, Target: dest}
	if err := w.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		return err
	}
	if err := bw.SetBuffered(false); err != nil {
		return err
	}
	s.w = w
	return nil
}

func (s *trojanPacketSession) ReadPacket() ([]byte, Target, error) {
	if s.r == nil {
		s.r = &trojan.PacketReader{Reader: s.conn}
	}
	return nextPacket(s.r, &s.pend)
}
