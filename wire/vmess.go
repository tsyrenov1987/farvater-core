package wire

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"hash/crc64"
	"io"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/xudp"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/encoding"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

var vmessCiphers = map[string]protocol.SecurityType{
	"auto":              protocol.SecurityType_AUTO,
	"aes-128-gcm":       protocol.SecurityType_AES128_GCM,
	"chacha20-poly1305": protocol.SecurityType_CHACHA20_POLY1305,
	"none":              protocol.SecurityType_NONE,
	"zero":              protocol.SecurityType_ZERO,
}

type vmessWire struct {
	spec PathSpec
	dest xnet.Destination
	mss  *internet.MemoryStreamConfig
	user *protocol.MemoryUser
	acc  *vmess.MemoryAccount
	seed int64 // the response drainer's behaviour, fixed per user as in Xray
}

func newVMess(spec PathSpec) (*vmessWire, error) {
	mss, err := buildStream(spec)
	if err != nil {
		return nil, err
	}
	cipher, ok := vmessCiphers[spec.Cipher]
	if !ok {
		cipher = protocol.SecurityType_AUTO // as Xray reads an unknown one
	}
	acc, err := (&vmess.Account{Id: spec.UUID, SecuritySettings: &protocol.SecurityConfig{Type: cipher}}).AsAccount()
	if err != nil {
		return nil, err
	}
	mem := acc.(*vmess.MemoryAccount)
	kdf := hmac.New(sha256.New, []byte("VMessBF"))
	kdf.Write(mem.ID.Bytes())
	return &vmessWire{
		spec: spec,
		dest: xnet.TCPDestination(xnet.ParseAddress(spec.Host), xnet.Port(spec.Port)),
		mss:  mss,
		user: &protocol.MemoryUser{Account: mem, Email: spec.ID},
		acc:  mem,
		seed: int64(crc64.Checksum(kdf.Sum(nil), crc64.MakeTable(crc64.ISO))),
	}, nil
}

func (w *vmessWire) ID() string           { return w.spec.ID }
func (w *vmessWire) Spec() PathSpec       { return w.spec }
func (w *vmessWire) NeedsHandshake() bool { return true }
func (w *vmessWire) Close() error         { return nil }

// request builds the header as Xray's own VMess client does: a chunked body,
// its lengths masked and padded under the AEAD ciphers.
func (w *vmessWire) request(cmd protocol.RequestCommand, addr xnet.Address, port xnet.Port) *protocol.RequestHeader {
	r := &protocol.RequestHeader{Version: encoding.Version, User: w.user, Command: cmd, Address: addr, Port: port,
		Option: protocol.RequestOptionChunkStream, Security: w.acc.Security}
	switch r.Security {
	case protocol.SecurityType_AES128_GCM, protocol.SecurityType_CHACHA20_POLY1305:
		r.Option.Set(protocol.RequestOptionChunkMasking)
		r.Option.Set(protocol.RequestOptionGlobalPadding)
	case protocol.SecurityType_NONE:
		r.Option.Set(protocol.RequestOptionChunkMasking)
	case protocol.SecurityType_ZERO:
		r.Security = protocol.SecurityType_NONE
		r.Option.Clear(protocol.RequestOptionChunkStream)
	}
	return r
}

// Dial establishes the outer transport. Nothing about the target is sent yet.
func (w *vmessWire) Dial(ctx context.Context) (Session, error) {
	conn, err := dialStream(ctx, "vmess", w.dest, w.mss)
	if err != nil {
		return nil, err
	}
	return &vmessSession{w: w, conn: conn}, nil
}

type vmessSession struct {
	w    *vmessWire
	conn stat.Connection
}

func (s *vmessSession) Close() error { return s.conn.Close() }

func (s *vmessSession) Run(ctx context.Context, target Target, prelude []byte, up <-chan []byte, down io.Writer, m Meter) (Outcome, error) {
	conn := s.conn
	defer conn.Close()
	request := s.w.request(protocol.RequestCommandTCP, xnet.ParseAddress(target.Host), xnet.Port(target.Port))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, IdleTimeout)
	go func() {
		<-ctx.Done()
		conn.Close() // unblocks the downstream reader
	}()

	sess := encoding.NewClientSession(ctx, s.w.seed)
	bw := buf.NewBufferedWriter(buf.NewWriter(conn))
	if err := sess.EncodeRequestHeader(request, bw); err != nil {
		return OutcomeError, err
	}
	body, err := sess.EncodeRequestBody(request, bw)
	if err != nil {
		return OutcomeError, err
	}
	if len(prelude) > 0 {
		if err := body.WriteMultiBuffer(buf.MergeBytes(nil, prelude)); err != nil {
			return OutcomeError, err
		}
	}
	if err := bw.SetBuffered(false); err != nil {
		return OutcomeError, err
	}

	upErr := make(chan error, 1)
	go func() {
		err := pumpUp(ctx, up, body, m, timer)
		if err == io.EOF && request.Option.Has(protocol.RequestOptionChunkStream) {
			_ = body.WriteMultiBuffer(buf.MultiBuffer{}) // the body's end: the server finishes upstream
		}
		upErr <- err
	}()
	downErr := make(chan error, 1)
	go func() {
		r := &buf.BufferedReader{Reader: buf.NewReader(conn)}
		if _, err := sess.DecodeResponseHeader(r); err != nil {
			downErr <- err
			return
		}
		body, err := sess.DecodeResponseBody(request, r)
		if err != nil {
			downErr <- err
			return
		}
		downErr <- buf.Copy(body, &downWriter{w: down, m: m}, buf.UpdateActivity(timer))
	}()
	return settle(ctx, upErr, downErr, cancel, timer, func() { timer.SetTimeout(2 * time.Second) })
}

// DialPacket establishes the outer transport for a UDP association. Datagrams
// travel as XUDP (Mux.Cool to v1.mux.cool:666), as Xray's own client sends
// them, naming each datagram's address.
func (w *vmessWire) DialPacket(ctx context.Context) (PacketSession, error) {
	conn, err := dialStream(ctx, "vmess", w.dest, w.mss)
	if err != nil {
		return nil, err
	}
	return &vmessPacketSession{
		conn:    conn,
		sess:    encoding.NewClientSession(ctx, w.seed),
		request: w.request(protocol.RequestCommandMux, xnet.DomainAddress("v1.mux.cool"), 666),
	}, nil
}

type vmessPacketSession struct {
	conn    stat.Connection
	sess    *encoding.ClientSession
	request *protocol.RequestHeader

	w    buf.Writer // set by the first WritePacket, which sends the request
	r    buf.Reader // set by the first ReadPacket, which reads the response header
	pend buf.MultiBuffer
}

func (s *vmessPacketSession) Close() error { return s.conn.Close() }

func (s *vmessPacketSession) WritePacket(p []byte, target Target) error {
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
	bw := buf.NewBufferedWriter(buf.NewWriter(s.conn))
	if err := s.sess.EncodeRequestHeader(s.request, bw); err != nil {
		b.Release()
		return err
	}
	body, err := s.sess.EncodeRequestBody(s.request, bw)
	if err != nil {
		b.Release()
		return err
	}
	w := xudp.NewPacketWriter(body, dest, [8]byte{})
	if err := w.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		return err
	}
	if err := bw.SetBuffered(false); err != nil {
		return err
	}
	s.w = w
	return nil
}

func (s *vmessPacketSession) ReadPacket() ([]byte, Target, error) {
	if s.r == nil {
		r := &buf.BufferedReader{Reader: buf.NewReader(s.conn)}
		if _, err := s.sess.DecodeResponseHeader(r); err != nil {
			return nil, Target{}, err
		}
		body, err := s.sess.DecodeResponseBody(s.request, r)
		if err != nil {
			return nil, Target{}, err
		}
		s.r = xudp.NewPacketReader(&buf.BufferedReader{Reader: body})
	}
	return nextPacket(s.r, &s.pend)
}
