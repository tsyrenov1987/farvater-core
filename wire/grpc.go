package wire

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// dialGRPC carries the tunnel as a gRPC bidirectional stream, the way Xray's
// client does: one HTTP/2 request to /<serviceName>/Tun with content-type
// application/grpc, whose body and response are streams of gRPC messages. The
// message is a Hunk — protobuf field 1, the tunnel bytes — which this core
// frames by hand, so it needs neither a protobuf runtime nor a gRPC library.
// Multi mode packs several Hunks into one MultiHunk message (repeated field
// 1); on the wire a one-element MultiHunk is identical to a Hunk, so the
// framing is shared and mode only changes the stream name.
func dialGRPC(ctx context.Context, s PathSpec) (net.Conn, error) {
	u, err := dialSecure(ctx, s, false)
	if err != nil {
		return nil, err
	}
	service := strings.TrimPrefix(s.ServiceName, "/")
	stream := "Tun"
	if s.Mode == "multi" {
		stream = "TunMulti"
	}
	authority := s.Authority
	if authority == "" {
		authority = s.ServerSNI()
	}
	reqURL := url.URL{Scheme: "https", Host: authority, Path: "/" + url.PathEscape(service) + "/" + stream}
	h := http.Header{}
	h.Set("Content-Type", "application/grpc")
	h.Set("TE", "trailers")
	h.Set("grpc-accept-encoding", "identity")
	browserHeaders(h, "fetch")
	st, err := openH2(ctx, u, http.MethodPost, reqURL.String(), h)
	if err != nil {
		u.Close()
		return nil, err
	}
	return &grpcConn{st: st, br: bufio.NewReader(st)}, nil
}

// grpcConn frames tunnel bytes as length-delimited gRPC Hunk messages over an
// HTTP/2 stream.
type grpcConn struct {
	st  *h2Stream
	br  *bufio.Reader
	rmu sync.Mutex
	wmu sync.Mutex
	rem []byte // payload of the current Hunk not yet returned by Read
}

func (c *grpcConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.rem) == 0 {
		msg, err := readGRPCMessage(c.br)
		if err != nil {
			return 0, err
		}
		data, err := hunkData(msg)
		if err != nil {
			return 0, err
		}
		c.rem = data
	}
	n := copy(p, c.rem)
	c.rem = c.rem[n:]
	return n, nil
}

func (c *grpcConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if _, err := c.st.Write(encodeGRPCHunk(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *grpcConn) Close() error                       { return c.st.Close() }
func (c *grpcConn) LocalAddr() net.Addr                { return c.st.LocalAddr() }
func (c *grpcConn) RemoteAddr() net.Addr               { return c.st.RemoteAddr() }
func (c *grpcConn) SetDeadline(t time.Time) error      { return nil }
func (c *grpcConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *grpcConn) SetWriteDeadline(t time.Time) error { return nil }

// encodeGRPCHunk wraps data as a gRPC message carrying a Hunk{data}: the
// 5-byte gRPC length prefix, then the one-field protobuf.
func encodeGRPCHunk(data []byte) []byte {
	inner := appendVarintField(nil, 1, data) // Hunk.data / MultiHunk.data[0]
	out := make([]byte, 5, 5+len(inner))
	out[0] = 0 // not compressed
	binary.BigEndian.PutUint32(out[1:], uint32(len(inner)))
	return append(out, inner...)
}

// readGRPCMessage reads one length-delimited gRPC message (its protobuf body).
func readGRPCMessage(r io.Reader) ([]byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	if head[0] != 0 {
		return nil, errors.New("grpc: compressed messages are not supported")
	}
	n := binary.BigEndian.Uint32(head[1:])
	if n > 16<<20 {
		return nil, errors.New("grpc: message too large")
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// hunkData returns the bytes of field 1 of a Hunk or MultiHunk message. A
// MultiHunk with several chunks is concatenated, which is what the stream
// carries anyway.
func hunkData(msg []byte) ([]byte, error) {
	var out []byte
	for len(msg) > 0 {
		tag, m, err := readVarint(msg)
		if err != nil {
			return nil, err
		}
		msg = m
		field, wtype := tag>>3, tag&7
		if wtype != 2 {
			return nil, errors.New("grpc: unexpected wire type in hunk")
		}
		ln, m, err := readVarint(msg)
		if err != nil {
			return nil, err
		}
		msg = m
		if uint64(len(msg)) < ln {
			return nil, io.ErrUnexpectedEOF
		}
		if field == 1 {
			out = append(out, msg[:ln]...)
		}
		msg = msg[ln:]
	}
	return out, nil
}

var _ net.Conn = (*grpcConn)(nil)
