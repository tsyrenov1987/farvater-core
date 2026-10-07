package wire

import (
	"context"
	"fmt"
	"net"
	"sync"
)

// outerTransport is a path's outer transport, shared across every flow of one wire.
// For grpc and xhttp it keeps one HTTP/2 connection (an h2Mux) and rides each
// flow's stream on it, the way Xray's client reuses a connection instead of
// handshaking per flow; tcp and ws dial a fresh connection per flow as before.
// The proxy protocol (VLESS/Trojan/VMess) runs on top of what dial returns.
// Vision is the exception: it needs the uTLS connection directly and dials with
// dialSecure.
type outerTransport struct {
	spec PathSpec
	mu   sync.Mutex
	mux  *h2Mux
}

func newOuterTransport(s PathSpec) *outerTransport { return &outerTransport{spec: s} }

// h2 returns the shared HTTP/2 connection manager, made on first use. Pings are
// left off (the library default): this layer only reuses the connection, so the
// wire looks as it did before bar the saved handshakes. Freeze-detection pacing
// is a kilvater concern, tuned there.
func (t *outerTransport) h2() *h2Mux {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.mux == nil {
		s := t.spec
		t.mux = newH2Mux(func(ctx context.Context) (net.Conn, error) {
			return dialSecure(ctx, s, false)
		}, 0, 0)
	}
	return t.mux
}

// dial establishes the outer transport and returns it as a net.Conn: the
// TLS/REALITY stream itself for raw TCP, or a stream over it for WebSocket,
// gRPC or XHTTP.
func (t *outerTransport) dial(ctx context.Context) (net.Conn, error) {
	switch t.spec.Network {
	case "tcp":
		return dialSecure(ctx, t.spec, false)
	case "ws":
		return dialWS(ctx, t.spec)
	case "grpc":
		return dialGRPC(ctx, t.h2(), t.spec)
	case "xhttp":
		return dialXHTTP(ctx, t.h2(), t.spec)
	default:
		return nil, fmt.Errorf("transport %q is not supported", t.spec.Network)
	}
}

// Close drops the shared connection, if one was ever made.
func (t *outerTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.mux != nil {
		return t.mux.Close()
	}
	return nil
}
