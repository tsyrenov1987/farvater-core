package wire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"sync"
)

type trojanWire struct {
	spec PathSpec
	key  []byte // the 56-hex-byte SHA-224 password hash Trojan sends
}

func newTrojan(spec PathSpec) (*trojanWire, error) {
	if spec.Network == "" {
		spec.Network = "tcp"
	}
	return &trojanWire{spec: spec, key: trojanKey(spec.Password)}, nil
}

// trojanKey is Trojan's password authenticator: the lowercase hex of the
// SHA-224 of the password, 56 bytes.
func trojanKey(password string) []byte {
	sum := sha256.Sum224([]byte(password))
	k := make([]byte, hex.EncodedLen(len(sum)))
	hex.Encode(k, sum[:])
	return k
}

func (w *trojanWire) ID() string           { return w.spec.ID }
func (w *trojanWire) Spec() PathSpec       { return w.spec }
func (w *trojanWire) NeedsHandshake() bool { return true }
func (w *trojanWire) Close() error         { return nil }

func (w *trojanWire) Dial(ctx context.Context) (Session, error) {
	conn, err := dialTransport(ctx, w.spec)
	if err != nil {
		return nil, err
	}
	return &trojanSession{w: w, conn: conn}, nil
}

type trojanSession struct {
	w    *trojanWire
	conn net.Conn
}

func (s *trojanSession) Close() error { return s.conn.Close() }

// trojanHeader is the request Trojan sends before the payload: the password
// hash, CRLF, the command (1 TCP, 3 UDP), the SOCKS-style address, CRLF.
func trojanHeader(key []byte, cmd byte, t Target) ([]byte, error) {
	b := append([]byte(nil), key...)
	b = append(b, '\r', '\n', cmd)
	b, err := appendSocksAddr(b, t)
	if err != nil {
		return nil, err
	}
	return append(b, '\r', '\n'), nil
}

func (s *trojanSession) Run(ctx context.Context, target Target, prelude []byte, up <-chan []byte, down io.Writer, m Meter) (Outcome, error) {
	head, err := trojanHeader(s.w.key, 1, target)
	if err != nil {
		s.conn.Close()
		return OutcomeError, err
	}
	// The header and the first payload leave together: the server reads the
	// header from its first read.
	if _, err := s.conn.Write(append(head, prelude...)); err != nil {
		s.conn.Close()
		return OutcomeError, err
	}
	return runStream(ctx, s.conn, s.conn, s.conn, up, down, m)
}

func (w *trojanWire) DialPacket(ctx context.Context) (PacketSession, error) {
	conn, err := dialTransport(ctx, w.spec)
	if err != nil {
		return nil, err
	}
	return &trojanPacketSession{conn: conn, key: w.key}, nil
}

// trojanPacketSession carries UDP as Trojan does: a header with command 3 to
// a placeholder address, then one framed datagram per packet (address,
// length, CRLF, payload), each naming its own destination.
type trojanPacketSession struct {
	conn net.Conn
	key  []byte

	wmu   sync.Mutex
	wrote bool
	rmu   sync.Mutex
}

func (s *trojanPacketSession) Close() error { return s.conn.Close() }

func (s *trojanPacketSession) WritePacket(p []byte, target Target) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	var out []byte
	if !s.wrote {
		head, err := trojanHeader(s.key, 3, target)
		if err != nil {
			return err
		}
		out = head
		s.wrote = true
	}
	frame, err := appendSocksAddr(nil, target)
	if err != nil {
		return err
	}
	frame = append(frame, byte(len(p)>>8), byte(len(p)), '\r', '\n')
	frame = append(frame, p...)
	_, err = s.conn.Write(append(out, frame...))
	return err
}

func (s *trojanPacketSession) ReadPacket() ([]byte, Target, error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	from, err := readSocksAddr(s.conn)
	if err != nil {
		return nil, Target{}, err
	}
	var lc [2]byte
	if _, err := io.ReadFull(s.conn, lc[:]); err != nil {
		return nil, Target{}, err
	}
	var crlf [2]byte
	if _, err := io.ReadFull(s.conn, crlf[:]); err != nil {
		return nil, Target{}, err
	}
	n := int(lc[0])<<8 | int(lc[1])
	p := make([]byte, n)
	if _, err := io.ReadFull(s.conn, p); err != nil {
		return nil, Target{}, err
	}
	return p, from, nil
}

var _ PacketWire = (*trojanWire)(nil)
