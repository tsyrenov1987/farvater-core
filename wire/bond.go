package wire

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tsyrenov1987/farvater-core/kilvater"
)

// A kilbond:// link is one path made of several kilvater links to the same
// server, each by its own route (a CDN relay, VK's call relays, ...). Every
// TCP flow on it is cut into chunks spread over all the legs at once and put
// back in order at the server (kilvater/bond.go), so the flow gets the sum of
// the routes, and survives one of them dropping:
//
//	kilbond://<anything>?leg=<base64url kilvater:// or vkturn:// link>&leg=...#name
//
// UDP takes the first leg alone. A server without bonds refuses the legs and
// the path fails as a whole, which the brain sees like any dead path.

// KindBond is a bonded kilvater path (Legs holds its legs).
const KindBond Kind = "kilbond"

func parseBond(raw string) (PathSpec, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return PathSpec{}, err
	}
	spec := PathSpec{Kind: KindBond}
	for _, l := range u.Query()["leg"] {
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(l, "="))
		if err != nil {
			return PathSpec{}, errors.New("kilbond: leg is not base64url")
		}
		ls, err := ParseURI(string(b))
		if err != nil {
			return PathSpec{}, fmt.Errorf("kilbond: leg: %w", err)
		}
		if ls.Kind != KindKilvater {
			return PathSpec{}, errors.New("kilbond: legs must be kilvater")
		}
		spec.Legs = append(spec.Legs, ls)
	}
	if len(spec.Legs) < 2 || len(spec.Legs) > 4 {
		return PathSpec{}, errors.New("kilbond: needs 2 to 4 legs")
	}
	first := spec.Legs[0]
	spec.Host, spec.Port, spec.SNI = first.Host, first.Port, first.SNI
	if f, err := url.PathUnescape(u.Fragment); err == nil && f != "" {
		spec.ID = f
	} else {
		spec.ID = "kilbond"
	}
	return spec, nil
}

type bondWire struct {
	spec PathSpec
	legs []*kilWire
}

func newBond(s PathSpec) (Wire, error) {
	ws := make([]*kilWire, 0, len(s.Legs))
	for _, ls := range s.Legs {
		ls := ls
		w, err := newKilWire(ls, func(ctx context.Context) (net.Conn, error) {
			return dialSecure(ctx, ls, false)
		})
		if err != nil {
			for _, o := range ws {
				o.Close()
			}
			return nil, err
		}
		ws = append(ws, w)
	}
	return &bondWire{spec: s, legs: ws}, nil
}

func (w *bondWire) ID() string           { return w.spec.ID }
func (w *bondWire) Spec() PathSpec       { return w.spec }
func (w *bondWire) NeedsHandshake() bool { return w.legs[0].NeedsHandshake() }

func (w *bondWire) Close() error {
	for _, l := range w.legs {
		l.Close()
	}
	return nil
}

func (w *bondWire) Refresh(t time.Time) {
	for _, l := range w.legs {
		l.Refresh(t)
	}
}

// Dial opens the first leg that opens; the others open when the flow starts.
func (w *bondWire) Dial(ctx context.Context) (Session, error) {
	var last error
	for i, l := range w.legs {
		st, err := l.openTunnel(ctx)
		if err == nil {
			return &bondSession{w: w, first: st, firstLeg: i}, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

// DialPacket: UDP rides the first leg alone.
func (w *bondWire) DialPacket(ctx context.Context) (PacketSession, error) {
	return w.legs[0].DialPacket(ctx)
}

var _ PacketWire = (*bondWire)(nil)

type bondSession struct {
	w        *bondWire
	first    net.Conn
	firstLeg int
	once     sync.Once
}

func (s *bondSession) Close() error {
	s.once.Do(func() { s.first.Close() })
	return nil
}

// bondLegRetry is how long a dead leg waits before it is opened again, and
// bondLegTries how many times in a row it may fail before it is let go.
var (
	bondLegRetry = time.Second
	bondLegTries = 4
)

func (s *bondSession) Run(ctx context.Context, target Target, prelude []byte, up <-chan []byte, down io.Writer, m Meter) (Outcome, error) {
	var sid [kilvater.SessionIDLen]byte
	rand.Read(sid[:])
	join := func(create bool) ([]byte, error) {
		var f byte
		if create {
			f = kilvater.JoinCreate
		}
		return kilvater.AppendJoin(nil, sid, f, kilvater.NetTCP, target.String())
	}
	if _, err := join(true); err != nil {
		s.Close()
		return OutcomeError, err
	}
	b := kilvater.NewBond()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Each leg is kept up while the flow lives: opened, joined, carried until
	// it fails, opened again after a pause. A leg the server never answered
	// on (a server without bonds, a refused key) is not tried again.
	var legsWG sync.WaitGroup
	alive := make(chan struct{}, len(s.w.legs)) // a leg ended
	everUp := make(chan struct{})
	var everOnce sync.Once
	for i := range s.w.legs {
		i := i
		legsWG.Add(1)
		go func() {
			defer legsWG.Done()
			defer func() { alive <- struct{}{} }()
			create, fails := true, 0
			for ctx.Err() == nil && !b.Done() {
				var st net.Conn
				var err error
				if i == s.firstLeg && create {
					st = s.first
				} else {
					st, err = s.w.legs[i].openTunnel(ctx)
				}
				accepted := false
				if err == nil {
					body, _ := join(create)
					if err = kilvater.WriteFrame(st, kilvater.FrameJoin, body); err == nil {
						accepted = b.RunLeg(st, false)
					} else {
						st.Close()
					}
				}
				if accepted {
					everOnce.Do(func() { close(everUp) })
					create, fails = false, 0
				} else if !create || fails >= bondLegTries {
					return
				} else {
					fails++
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(bondLegRetry):
				}
			}
		}()
	}
	// The flow fails when every leg has given up.
	go func() {
		for n := 0; n < len(s.w.legs); n++ {
			select {
			case <-alive:
			case <-ctx.Done():
				return
			}
		}
		b.Abort(1, ErrWireDead)
	}()
	defer func() {
		b.Close()
		cancel()
		legsWG.Wait()
	}()

	if len(prelude) > 0 {
		if _, err := b.Write(prelude); err != nil {
			return OutcomeError, err
		}
	}
	it := newIdleTimer(IdleTimeout, cancel)
	defer it.stop()
	go func() {
		<-ctx.Done()
		b.Abort(0, ctx.Err()) // unblocks the downstream reader; the far end just closes
	}()
	upErr := make(chan error, 1)
	go func() { upErr <- pumpUp(ctx, up, b, m, it) }()
	downErr := make(chan error, 1)
	go func() {
		err := pumpDown(b, down, m, it)
		if err != nil {
			select {
			case <-everUp:
			default:
				err = ErrWireDead // no leg ever got through: the path is dead, not the flow
			}
		}
		downErr <- err
	}()
	return settle(ctx, upErr, downErr, cancel, func() {
		it.setTimeout(2 * time.Second)
		b.CloseWrite()
	})
}
