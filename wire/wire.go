package wire

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
)

// Target is the destination the app asked for.
type Target struct {
	Host string
	Port int
}

func (t Target) String() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

// Meter receives the byte-level events a flow produces. The switchboard turns
// them into a receipt; wires never interpret them.
type Meter interface {
	// Up is called with every chunk about to be sent upstream (the prelude the
	// caller passed to Run is not reported again).
	Up(p []byte)
	// Down is called with the size of every chunk that arrived downstream,
	// before it is written to the app.
	Down(n int)
}

// Outcome says how a flow ended.
type Outcome int

const (
	OutcomeRemoteFin Outcome = iota // the remote side finished first
	OutcomeClientFin                // the app finished first and the remote drained
	OutcomeError                    // the transport failed
	OutcomeCanceled                 // the caller canceled the context
)

func (o Outcome) String() string {
	switch o {
	case OutcomeRemoteFin:
		return "remote_fin"
	case OutcomeClientFin:
		return "client_fin"
	case OutcomeError:
		return "error"
	}
	return "canceled"
}

// ErrWireDead is returned by Run when the long-lived transport session behind a
// wire turned out to be dead (the caller should count it as a wire failure).
var ErrWireDead = errors.New("wire: transport session is dead")

// Session is one established outer transport, ready to carry exactly one flow.
type Session interface {
	// Run sends the proxy request for target, forwards prelude, then pumps
	// bytes between up/down and the remote until one side finishes. up is
	// closed by the caller when the app has nothing more to send.
	Run(ctx context.Context, target Target, prelude []byte, up <-chan []byte, down io.Writer, m Meter) (Outcome, error)
	Close() error
}

// Wire carries flows to one server over one transport. It holds no opinion
// about when it should be used.
type Wire interface {
	ID() string
	Spec() PathSpec
	// NeedsHandshake reports whether the next Dial performs a fresh TLS/QUIC
	// handshake (the caller paces those).
	NeedsHandshake() bool
	Dial(ctx context.Context) (Session, error)
	Close() error
}

// Build makes a wire for a parsed path.
func Build(spec PathSpec) (Wire, error) {
	switch spec.Kind {
	case KindVLESS:
		return newVLESS(spec)
	case KindHysteria2:
		return newHysteria(spec)
	}
	return nil, errors.New("wire: unsupported kind " + string(spec.Kind))
}
