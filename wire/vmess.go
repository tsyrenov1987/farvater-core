package wire

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// VMess security (the body cipher the client picks; the server follows the
// security byte).
const (
	vmessAES128GCM = 3
	vmessChacha    = 4
	vmessNone      = 5
	vmessAuto      = 2
	vmessZero      = 6
)

// VMess request options.
const (
	optChunkStream   = 0x01
	optChunkMasking  = 0x04
	optGlobalPadding = 0x08
)

type vmessWire struct {
	spec   PathSpec
	uuid   []byte
	cmdKey []byte
	sec    byte
	tr     *outerTransport
}

func newVMess(spec PathSpec) (*vmessWire, error) {
	if spec.Network == "" {
		spec.Network = "tcp"
	}
	uuid, err := parseUUID(spec.UUID)
	if err != nil {
		return nil, err
	}
	return &vmessWire{spec: spec, uuid: uuid, cmdKey: vmessCmdKey(uuid), sec: vmessSecurity(spec.Cipher), tr: newOuterTransport(spec)}, nil
}

// vmessSecurity maps a link's cipher name to the security byte. auto (and an
// unknown value) picks AES-GCM: our targets have hardware AES, and the server
// follows whatever the client sends.
func vmessSecurity(name string) byte {
	switch name {
	case "aes-128-gcm":
		return vmessAES128GCM
	case "chacha20-poly1305":
		return vmessChacha
	case "none":
		return vmessNone
	case "zero":
		return vmessZero
	default:
		return vmessAES128GCM
	}
}

func (w *vmessWire) ID() string           { return w.spec.ID }
func (w *vmessWire) Spec() PathSpec       { return w.spec }
func (w *vmessWire) NeedsHandshake() bool { return true }
func (w *vmessWire) Close() error         { return w.tr.Close() }
func (w *vmessWire) Refresh(t time.Time)  { w.tr.Refresh(t) }

func (w *vmessWire) Dial(ctx context.Context) (Session, error) {
	conn, err := w.tr.dial(ctx)
	if err != nil {
		return nil, err
	}
	return &vmessSession{w: w, conn: conn}, nil
}

type vmessSession struct {
	w    *vmessWire
	conn net.Conn
}

func (s *vmessSession) Close() error { return s.conn.Close() }

// vmessConn holds the per-connection keys and the resolved options.
type vmessConn struct {
	reqKey, reqIV   [16]byte
	respKey, respIV [16]byte
	respHeader      byte
	sec             byte
	option          byte
}

func newVMessConn(sec byte) (*vmessConn, error) {
	var seed [33]byte
	if _, err := cryptoRead(seed[:]); err != nil {
		return nil, err
	}
	c := &vmessConn{sec: sec}
	copy(c.reqKey[:], seed[:16])
	copy(c.reqIV[:], seed[16:32])
	c.respHeader = seed[32]
	rk := sha256.Sum256(c.reqKey[:])
	copy(c.respKey[:], rk[:16])
	ri := sha256.Sum256(c.reqIV[:])
	copy(c.respIV[:], ri[:16])
	switch sec {
	case vmessAES128GCM, vmessChacha:
		c.option = optChunkStream | optChunkMasking | optGlobalPadding
	case vmessNone:
		c.option = optChunkStream | optChunkMasking
	case vmessZero:
		c.sec = vmessNone
		c.option = 0
	}
	return c, nil
}

// header builds the VMess request header (before AEAD sealing): the version,
// the keys, the response header byte, the options, the security, the command
// and address, a random padding, and the FNV1a checksum.
func (c *vmessConn) header(cmd byte, t *Target) ([]byte, error) {
	b := []byte{1}
	b = append(b, c.reqIV[:]...)
	b = append(b, c.reqKey[:]...)
	b = append(b, c.respHeader, c.option)
	padLen := rand.IntN(16)
	b = append(b, byte(padLen<<4)|c.sec, 0, cmd)
	if t != nil {
		var err error
		if b, err = appendPortAddr(b, *t); err != nil {
			return nil, err
		}
	}
	if padLen > 0 {
		pad := make([]byte, padLen)
		if _, err := cryptoRead(pad); err != nil {
			return nil, err
		}
		b = append(b, pad...)
	}
	var sum [4]byte
	binary.BigEndian.PutUint32(sum[:], fnv1a32(b))
	return append(b, sum[:]...), nil
}

// bodyWriter and bodyReader build the chunk stream for this connection's
// security and options.
func (c *vmessConn) bodyWriter(w io.Writer, cmd byte) (*vmessChunkWriter, error) {
	if c.option&optChunkStream == 0 {
		return nil, nil // zero: raw
	}
	cw := &vmessChunkWriter{w: w, payload: 8192}
	if c.option&optChunkMasking != 0 {
		cw.size = newShakeSizeParser(c.reqIV[:])
	}
	cw.padding = c.option&optGlobalPadding != 0
	aead, err := c.cipher(c.reqKey[:], c.reqIV[:])
	if err != nil {
		return nil, err
	}
	cw.aead, cw.nonce = aead.aead, aead.nonce
	cw.payload = 8192 - aead.aead.Overhead() - 2 - 64
	return cw, nil
}

func (c *vmessConn) bodyReader(r io.Reader) (*vmessChunkReader, error) {
	if c.option&optChunkStream == 0 {
		return nil, nil
	}
	cr := &vmessChunkReader{r: r}
	if c.option&optChunkMasking != 0 {
		cr.size = newShakeSizeParser(c.respIV[:])
	}
	cr.padding = c.option&optGlobalPadding != 0
	aead, err := c.cipher(c.respKey[:], c.respIV[:])
	if err != nil {
		return nil, err
	}
	cr.aead, cr.nonce = aead.aead, aead.nonce
	return cr, nil
}

func (c *vmessConn) cipher(key, iv []byte) (*vmessAEAD, error) {
	switch c.sec {
	case vmessChacha:
		a, err := chacha20poly1305.New(vmessChachaKey(key))
		if err != nil {
			return nil, err
		}
		return &vmessAEAD{aead: a, iv: iv}, nil
	case vmessNone:
		return &vmessAEAD{aead: noopAEAD{}, iv: iv}, nil
	default:
		a, err := newAESGCM(key)
		if err != nil {
			return nil, err
		}
		return &vmessAEAD{aead: a, iv: iv}, nil
	}
}

// readResponseHeader reads and verifies the AEAD response header.
func (c *vmessConn) readResponseHeader(r io.Reader) error {
	lenKey := vmessKDF16(c.respKey[:], "AEAD Resp Header Len Key")
	lenIV := vmessKDF(c.respIV[:], "AEAD Resp Header Len IV")[:12]
	lenAEAD, err := newAESGCM(lenKey)
	if err != nil {
		return err
	}
	var encLen [18]byte
	if _, err := io.ReadFull(r, encLen[:]); err != nil {
		return err
	}
	lenPlain, err := lenAEAD.Open(nil, lenIV, encLen[:], nil)
	if err != nil {
		return errors.New("vmess: cannot decrypt response length")
	}
	n := int(binary.BigEndian.Uint16(lenPlain))

	payKey := vmessKDF16(c.respKey[:], "AEAD Resp Header Key")
	payIV := vmessKDF(c.respIV[:], "AEAD Resp Header IV")[:12]
	payAEAD, err := newAESGCM(payKey)
	if err != nil {
		return err
	}
	encPay := make([]byte, n+16)
	if _, err := io.ReadFull(r, encPay); err != nil {
		return err
	}
	payload, err := payAEAD.Open(nil, payIV, encPay, nil)
	if err != nil {
		return errors.New("vmess: cannot decrypt response header")
	}
	if len(payload) < 1 || payload[0] != c.respHeader {
		return errors.New("vmess: wrong response header")
	}
	return nil
}

func (s *vmessSession) Run(ctx context.Context, target Target, prelude []byte, up <-chan []byte, down io.Writer, m Meter) (Outcome, error) {
	c, err := newVMessConn(s.w.sec)
	if err != nil {
		s.conn.Close()
		return OutcomeError, err
	}
	hdr, err := c.header(1, &target)
	if err != nil {
		s.conn.Close()
		return OutcomeError, err
	}
	sealed, err := sealVMessAEADHeader(s.w.cmdKey, hdr, time.Now().Unix())
	if err != nil {
		s.conn.Close()
		return OutcomeError, err
	}
	if _, err := s.conn.Write(sealed); err != nil {
		s.conn.Close()
		return OutcomeError, err
	}
	bw, err := c.bodyWriter(s.conn, 1)
	if err != nil {
		s.conn.Close()
		return OutcomeError, err
	}
	var body io.Writer = s.conn
	if bw != nil {
		body = bw
	}
	if len(prelude) > 0 {
		if _, err := body.Write(prelude); err != nil {
			s.conn.Close()
			return OutcomeError, err
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	it := newIdleTimer(IdleTimeout, cancel)
	defer it.stop()
	stop := context.AfterFunc(ctx, func() { s.conn.Close() })
	defer stop()
	upErr := make(chan error, 1)
	go func() {
		err := pumpUp(ctx, up, body, m, it)
		if err == io.EOF && bw != nil {
			_ = bw.end() // the body's end marker; the server then finishes upstream
		}
		upErr <- err
	}()
	downErr := make(chan error, 1)
	go func() {
		if err := c.readResponseHeader(s.conn); err != nil {
			downErr <- err
			return
		}
		br, err := c.bodyReader(s.conn)
		if err != nil {
			downErr <- err
			return
		}
		var rd io.Reader = s.conn
		if br != nil {
			rd = br
		}
		downErr <- pumpDown(rd, down, m, it)
	}()
	return settleClose(ctx, s.conn, upErr, downErr, cancel, func() { it.setTimeout(2 * time.Second) })
}

func (w *vmessWire) DialPacket(ctx context.Context) (PacketSession, error) {
	conn, err := w.tr.dial(ctx)
	if err != nil {
		return nil, err
	}
	return &vmessPacketSession{w: w, conn: conn}, nil
}

type vmessPacketSession struct {
	w         *vmessWire
	conn      net.Conn
	writeOnce sync.Once
	readOnce  sync.Once
	c         *vmessConn
	init      error
	xw        *xudpWriter
	xr        *xudpReader
}

func (s *vmessPacketSession) Close() error { return s.conn.Close() }

// writeInit seals and sends the VMess Mux request header and sets up the
// XUDP writer over the body chunk stream. It does not read the response.
func (s *vmessPacketSession) writeInit() {
	c, err := newVMessConn(s.w.sec)
	if err != nil {
		s.init = err
		return
	}
	s.c = c
	hdr, err := c.header(3, nil) // Mux
	if err != nil {
		s.init = err
		return
	}
	sealed, err := sealVMessAEADHeader(s.w.cmdKey, hdr, time.Now().Unix())
	if err != nil {
		s.init = err
		return
	}
	if _, err := s.conn.Write(sealed); err != nil {
		s.init = err
		return
	}
	bw, err := c.bodyWriter(s.conn, 3)
	if err != nil {
		s.init = err
		return
	}
	var body io.Writer = s.conn
	if bw != nil {
		body = bw
	}
	s.xw = newXUDPWriter(body)
}

// readInit ensures the request is out, then reads the VMess response header
// and sets up the XUDP reader over the body chunk stream.
func (s *vmessPacketSession) readInit() {
	s.writeOnce.Do(s.writeInit)
	if s.init != nil {
		return
	}
	if err := s.c.readResponseHeader(s.conn); err != nil {
		s.init = err
		return
	}
	br, err := s.c.bodyReader(s.conn)
	if err != nil {
		s.init = err
		return
	}
	var rd io.Reader = s.conn
	if br != nil {
		rd = br
	}
	s.xr = newXUDPReader(rd)
}

func (s *vmessPacketSession) WritePacket(p []byte, target Target) error {
	s.writeOnce.Do(s.writeInit)
	if s.init != nil {
		return s.init
	}
	return s.xw.WritePacket(p, target)
}

func (s *vmessPacketSession) ReadPacket() ([]byte, Target, error) {
	s.readOnce.Do(s.readInit)
	if s.init != nil {
		return nil, Target{}, s.init
	}
	return s.xr.ReadPacket()
}

var _ PacketWire = (*vmessWire)(nil)

func cryptoRead(b []byte) (int, error) { return cryptorand.Read(b) }
