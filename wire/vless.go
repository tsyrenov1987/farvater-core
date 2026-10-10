package wire

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// IdleTimeout closes a flow with no traffic in either direction.
var IdleTimeout = 5 * time.Minute

// visionFlow is the flow name that turns on Vision.
const visionFlow = "xtls-rprx-vision"

type vlessWire struct {
	spec   PathSpec
	uuid   []byte
	vision bool
	tr     *outerTransport
}

func newVLESS(spec PathSpec) (*vlessWire, error) {
	if spec.Network == "" {
		spec.Network = "tcp"
	}
	uuid, err := parseUUID(spec.UUID)
	if err != nil {
		return nil, err
	}
	vision := spec.Flow == visionFlow
	if vision && spec.Network != "tcp" {
		return nil, errors.New("xtls-rprx-vision needs a raw TCP transport")
	}
	return &vlessWire{spec: spec, uuid: uuid, vision: vision, tr: newOuterTransport(spec)}, nil
}

func (w *vlessWire) ID() string           { return w.spec.ID }
func (w *vlessWire) Spec() PathSpec       { return w.spec }
func (w *vlessWire) NeedsHandshake() bool { return w.tr.needsHandshake() }
func (w *vlessWire) Close() error         { return w.tr.Close() }
func (w *vlessWire) Refresh(t time.Time)  { w.tr.Refresh(t) }

func (w *vlessWire) Dial(ctx context.Context) (Session, error) {
	if w.vision {
		u, err := dialSecure(ctx, w.spec, false)
		if err != nil {
			return nil, err
		}
		return &vlessSession{w: w, conn: u, utls: u}, nil
	}
	conn, err := w.tr.dial(ctx)
	if err != nil {
		return nil, err
	}
	return &vlessSession{w: w, conn: conn}, nil
}

type vlessSession struct {
	w    *vlessWire
	conn net.Conn
	utls *utls.UConn // set only for Vision, which needs the raw TLS buffers
}

func (s *vlessSession) Close() error { return s.conn.Close() }

// vlessHeader is the VLESS request: version 0, the UUID, the addons (the flow
// name for Vision, else none), the command, then the destination (omitted for
// Mux). cmd: 1 TCP, 2 UDP, 3 Mux.
func vlessHeader(uuid []byte, cmd byte, vision bool, t *Target) ([]byte, error) {
	b := append([]byte{0}, uuid...)
	if vision {
		addons := appendVarintField(nil, 1, []byte(visionFlow)) // Addons.Flow
		b = append(b, byte(len(addons)))
		b = append(b, addons...)
	} else {
		b = append(b, 0)
	}
	b = append(b, cmd)
	if t != nil {
		var err error
		if b, err = appendPortAddr(b, *t); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// readVLESSResponse reads the response header: version, then the addons the
// server echoes (a length byte and that many bytes).
func readVLESSResponse(r io.Reader) error {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return err
	}
	if h[0] != 0 {
		return errors.New("vless: unexpected response version")
	}
	if n := int(h[1]); n > 0 {
		if _, err := io.ReadFull(r, make([]byte, n)); err != nil {
			return err
		}
	}
	return nil
}

func (s *vlessSession) Run(ctx context.Context, target Target, prelude []byte, up <-chan []byte, down io.Writer, m Meter) (Outcome, error) {
	head, err := vlessHeader(s.w.uuid, 1, s.w.vision, &target)
	if err != nil {
		s.conn.Close()
		return OutcomeError, err
	}
	if !s.w.vision {
		if _, err := s.conn.Write(append(head, prelude...)); err != nil {
			s.conn.Close()
			return OutcomeError, err
		}
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		it := newIdleTimer(IdleTimeout, cancel)
		defer it.stop()
		stop := context.AfterFunc(ctx, func() { s.conn.Close() })
		defer stop()
		upErr := make(chan error, 1)
		go func() { upErr <- pumpUp(ctx, up, s.conn, m, it) }()
		downErr := make(chan error, 1)
		go func() {
			if err := readVLESSResponse(s.conn); err != nil {
				downErr <- err
				return
			}
			downErr <- pumpDown(s.conn, down, m, it)
		}()
		return settleClose(ctx, s.conn, upErr, downErr, cancel, func() { it.setTimeout(2 * time.Second) })
	}
	return s.runVision(ctx, head, prelude, up, down, m)
}

func (s *vlessSession) runVision(ctx context.Context, head, prelude []byte, up <-chan []byte, down io.Writer, m Meter) (Outcome, error) {
	st := newVisionState(s.w.uuid)
	drain, raw, err := utlsBuffers(s.utls)
	if err != nil {
		s.conn.Close()
		return OutcomeError, err
	}
	// The VLESS header goes out plain; the first body frame carries the UUID.
	if _, err := s.conn.Write(head); err != nil {
		s.conn.Close()
		return OutcomeError, err
	}
	vw := newVisionWriter(s.conn, s.utls.NetConn(), st)
	if err := vw.writeFirst(prelude); err != nil {
		s.conn.Close()
		return OutcomeError, err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	it := newIdleTimer(IdleTimeout, cancel)
	defer it.stop()
	stop := context.AfterFunc(ctx, func() { s.conn.Close() })
	defer stop()
	upErr := make(chan error, 1)
	go func() { upErr <- pumpUp(ctx, up, vw, m, it) }()
	downErr := make(chan error, 1)
	go func() {
		if err := readVLESSResponse(s.conn); err != nil {
			downErr <- err
			return
		}
		vr := newVisionReader(s.conn, st, raw, drain)
		downErr <- pumpDown(vr, down, m, it)
	}()
	return settleClose(ctx, s.conn, upErr, downErr, cancel, func() { it.setTimeout(2 * time.Second) })
}

// DialPacket carries UDP as XUDP (Mux.Cool to v1.mux.cool:666), framed as
// Vision needs it when the flow is Vision.
func (w *vlessWire) DialPacket(ctx context.Context) (PacketSession, error) {
	var conn net.Conn
	var u *utls.UConn
	var err error
	if w.vision {
		u, err = dialSecure(ctx, w.spec, false)
		conn = u
	} else {
		conn, err = w.tr.dial(ctx)
	}
	if err != nil {
		return nil, err
	}
	return &vlessPacketSession{w: w, conn: conn, utls: u}, nil
}

type vlessPacketSession struct {
	w    *vlessWire
	conn net.Conn
	utls *utls.UConn

	writeOnce sync.Once
	readOnce  sync.Once
	st        *visionState // Vision only, shared by the writer and reader
	drain     func() []byte
	raw       io.Reader
	init      error
	xw        *xudpWriter
	xr        *xudpReader
}

func (s *vlessPacketSession) Close() error { return s.conn.Close() }

// writeInit sends the VLESS Mux request header and sets up the XUDP writer.
// For Vision it also makes the shared state and the writer that pads the
// uplink. It does not read the response; that is readInit's job, so writing
// the request and reading the reply never wait on each other.
func (s *vlessPacketSession) writeInit() {
	head, err := vlessHeader(s.w.uuid, 3, s.w.vision, nil) // Mux: no address
	if err != nil {
		s.init = err
		return
	}
	if _, err := s.conn.Write(head); err != nil {
		s.init = err
		return
	}
	if s.w.vision {
		s.st = newVisionState(s.w.uuid)
		s.drain, s.raw, err = utlsBuffers(s.utls)
		if err != nil {
			s.init = err
			return
		}
		s.xw = newXUDPWriter(newVisionWriter(s.conn, nil, s.st))
		return
	}
	s.xw = newXUDPWriter(s.conn)
}

// readInit makes sure the request header is out, then reads the VLESS
// response header and sets up the XUDP reader.
func (s *vlessPacketSession) readInit() {
	s.writeOnce.Do(s.writeInit)
	if s.init != nil {
		return
	}
	if err := readVLESSResponse(s.conn); err != nil {
		s.init = err
		return
	}
	if s.w.vision {
		s.xr = newXUDPReader(newVisionReader(s.conn, s.st, s.raw, s.drain))
		return
	}
	s.xr = newXUDPReader(s.conn)
}

func (s *vlessPacketSession) WritePacket(p []byte, target Target) error {
	s.writeOnce.Do(s.writeInit)
	if s.init != nil {
		return s.init
	}
	return s.xw.WritePacket(p, target)
}

func (s *vlessPacketSession) ReadPacket() ([]byte, Target, error) {
	s.readOnce.Do(s.readInit)
	if s.init != nil {
		return nil, Target{}, s.init
	}
	return s.xr.ReadPacket()
}

// parseUUID reads a UUID in the 8-4-4-4-12 hex form, or derives one from an
// arbitrary string the way Xray does (SHA-1, version/variant bits set).
func parseUUID(s string) ([]byte, error) {
	clean := strings.ReplaceAll(s, "-", "")
	if len(clean) == 32 {
		b, err := hex.DecodeString(clean)
		if err == nil && len(b) == 16 {
			return b, nil
		}
	}
	if s == "" {
		return nil, errors.New("vless: empty uuid")
	}
	return deriveUUID(s), nil
}

// deriveUUID maps an arbitrary string to a UUID, as Xray does for a
// non-standard id: SHA-1 of 16 zero bytes followed by the string, with the
// version (5) and variant bits set.
func deriveUUID(s string) []byte {
	h := sha1.New()
	h.Write(make([]byte, 16))
	h.Write([]byte(s))
	u := h.Sum(nil)[:16]
	u[6] = (u[6] & 0x0f) | (5 << 4)
	u[8] = (u[8] & 0x3f) | 0x80
	return u
}

var _ PacketWire = (*vlessWire)(nil)
