package wire

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// A hosted path is one whose transport the app runs beside the core: an
// olcRTC call needs a WebRTC stack the core does not link, and a crash in it
// must not take the tunnel down. While the transport is up, the app hands the
// core its loopback SOCKS5 door; the core carries flows through the door and
// keeps all its judgement of the path.

// IsHosted reports whether paths of kind k are run by the app, not the core.
func IsHosted(k Kind) bool { return k == KindOlcRTC }

// Endpoint is a hosted path's door: "127.0.0.1:port" and the RFC 1929
// credentials it admits. The zero Endpoint means the transport is down.
type Endpoint struct{ Addr, User, Pass string }

// HostedWire is the wire of a hosted path.
type HostedWire interface {
	Wire
	SetEndpoint(Endpoint)
	Up() bool
}

// ErrNotUp is returned by Dial while the app has not brought the path up.
var ErrNotUp = errors.New("wire: hosted path is not up")

type hostedWire struct {
	spec PathSpec
	mu   sync.Mutex
	ep   Endpoint
}

func newHosted(spec PathSpec) *hostedWire { return &hostedWire{spec: spec} }

func (w *hostedWire) ID() string     { return w.spec.ID }
func (w *hostedWire) Spec() PathSpec { return w.spec }

// NeedsHandshake: the door is on loopback; the call's own handshakes are the app's.
func (w *hostedWire) NeedsHandshake() bool { return false }
func (w *hostedWire) Close() error         { return nil }

func (w *hostedWire) SetEndpoint(ep Endpoint) {
	w.mu.Lock()
	w.ep = ep
	w.mu.Unlock()
}

func (w *hostedWire) Up() bool { return w.endpoint().Addr != "" }

func (w *hostedWire) endpoint() Endpoint {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.ep
}

// Dial opens the door and authenticates. The target goes in Run.
func (w *hostedWire) Dial(ctx context.Context) (Session, error) {
	ep := w.endpoint()
	if ep.Addr == "" {
		return nil, ErrNotUp
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", ep.Addr)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if err := socksLogin(conn, ep.User, ep.Pass); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return &hostedSession{conn: conn}, nil
}

type hostedSession struct{ conn net.Conn }

func (s *hostedSession) Close() error { return s.conn.Close() }

func (s *hostedSession) Run(ctx context.Context, target Target, prelude []byte, up <-chan []byte, down io.Writer, m Meter) (Outcome, error) {
	conn := s.conn
	stop := context.AfterFunc(ctx, func() { conn.Close() }) // unblocks the door's answer

	// The door answers once the far end has reached the target.
	if err := socksConnect(conn, target); err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return OutcomeCanceled, ctx.Err()
		}
		return OutcomeError, err
	}
	stop()
	if len(prelude) > 0 {
		if _, err := conn.Write(prelude); err != nil {
			conn.Close()
			return OutcomeError, err
		}
	}
	return runStream(ctx, conn, conn, conn, up, down, m)
}

// socksLogin is the client side of the SOCKS5 greeting (RFC 1928), with
// username/password authentication (RFC 1929) when user is set.
func socksLogin(c net.Conn, user, pass string) error {
	method := byte(0x00)
	if user != "" {
		method = 0x02
	}
	if _, err := c.Write([]byte{0x05, 0x01, method}); err != nil {
		return err
	}
	var r [2]byte
	if _, err := io.ReadFull(c, r[:]); err != nil {
		return err
	}
	if r[0] != 0x05 || r[1] != method {
		return fmt.Errorf("socks: method %#x refused", method)
	}
	if method == 0x00 {
		return nil
	}
	if len(user) > 255 || len(pass) > 255 {
		return errors.New("socks: credentials too long")
	}
	req := append([]byte{0x01, byte(len(user))}, user...)
	req = append(append(req, byte(len(pass))), pass...)
	if _, err := c.Write(req); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, r[:]); err != nil {
		return err
	}
	if r[1] != 0x00 {
		return errors.New("socks: authentication refused")
	}
	return nil
}

// socksConnect sends CONNECT for t and reads the reply.
func socksConnect(c net.Conn, t Target) error {
	req := []byte{0x05, 0x01, 0x00}
	if ip, err := netip.ParseAddr(t.Host); err == nil {
		if ip.Is4() || ip.Is4In6() {
			req = append(req, 0x01)
			ip = ip.Unmap()
		} else {
			req = append(req, 0x04)
		}
		req = append(req, ip.AsSlice()...)
	} else {
		if len(t.Host) > 255 {
			return errors.New("socks: host name too long")
		}
		req = append(append(req, 0x03, byte(len(t.Host))), t.Host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(t.Port))
	if _, err := c.Write(req); err != nil {
		return err
	}
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return err
	}
	if h[0] != 0x05 {
		return errors.New("socks: bad reply")
	}
	if h[1] != 0x00 {
		return fmt.Errorf("socks: connect refused (reply %d)", h[1])
	}
	var skip int
	switch h[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return err
		}
		skip = int(n[0])
	default:
		return errors.New("socks: bad reply address")
	}
	_, err := io.ReadFull(c, make([]byte, skip+2)) // bound address and port
	return err
}
