package wire

import (
	"context"
	"fmt"
	"net"
)

// dialTransport establishes a path's outer transport and returns it as a
// net.Conn: the TLS/REALITY stream itself for raw TCP, or a stream over it
// for WebSocket, gRPC or XHTTP. The proxy protocol (VLESS/Trojan/VMess) runs
// on top of what this returns. Vision is the exception: it needs the uTLS
// connection directly and dials with dialSecure.
func dialTransport(ctx context.Context, s PathSpec) (net.Conn, error) {
	switch s.Network {
	case "tcp":
		u, err := dialSecure(ctx, s, false)
		if err != nil {
			return nil, err
		}
		return u, nil
	case "ws":
		return dialWS(ctx, s)
	case "grpc":
		return dialGRPC(ctx, s)
	case "xhttp":
		return dialXHTTP(ctx, s)
	default:
		return nil, fmt.Errorf("transport %q is not supported", s.Network)
	}
}
