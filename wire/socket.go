package wire

import (
	"context"
	"net"
	"syscall"
	"time"
)

// SocketControl, when set, runs on every socket the core opens to the network
// (paths, Russian-direct dials, probes). The desktop client sets it to pin those
// sockets to the physical interface: its tunnel takes the default route, and a
// path's own connection must not loop back into it. Mobile leaves it nil — the
// system keeps the tunnel's own sockets off the tunnel there.
var SocketControl func(network, address string, c syscall.RawConn) error

// NewDialer is a net.Dialer that applies SocketControl.
func NewDialer(timeout time.Duration) net.Dialer {
	return net.Dialer{Timeout: timeout, Control: SocketControl}
}

// ListenUDP opens an unconnected UDP socket that applies SocketControl.
func ListenUDP() (*net.UDPConn, error) {
	if SocketControl == nil {
		return net.ListenUDP("udp", nil)
	}
	lc := net.ListenConfig{Control: SocketControl}
	pc, err := lc.ListenPacket(context.Background(), "udp", ":0")
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}
