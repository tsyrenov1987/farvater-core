package desktop

import (
	"context"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/tsyrenov1987/farvater-core/wire"
)

// Options is what Up needs to know beyond the machine itself.
type Options struct {
	// Nodes are the addresses of the catalogue's servers: the kill switch lets
	// the core reach them on the physical network and nothing else foreign.
	Nodes []netip.Addr
	// KillSwitch keeps the machine off the network outside the tunnel, also
	// when the program dies without cleaning up (until `off` or a clean run).
	KillSwitch bool
	Logf       func(string, ...any)
}

// tunPackets adapts a wireguard tun.Device (one packet per call; the offset
// leaves room for the 4-byte header utun wants).
type tunPackets struct {
	dev     tun.Device
	rb, wb  [][]byte
	rs      []int
	closing atomic.Bool
}

const tunOffset = 16

func newTunPackets(dev tun.Device) *tunPackets {
	return &tunPackets{dev: dev, rb: [][]byte{make([]byte, tunOffset+65535)}, wb: make([][]byte, 1), rs: make([]int, 1)}
}

func (t *tunPackets) ReadPacket(b []byte) (int, error) {
	n, err := t.dev.Read(t.rb, t.rs, tunOffset)
	if err != nil || n == 0 {
		return 0, err
	}
	return copy(b, t.rb[0][tunOffset:tunOffset+t.rs[0]]), nil
}

func (t *tunPackets) WritePacket(b []byte) error {
	buf := make([]byte, tunOffset+len(b))
	copy(buf[tunOffset:], b)
	t.wb[0] = buf
	_, err := t.dev.Write(t.wb, tunOffset)
	return err
}

// pinResolver makes the core's own name lookups (Russian sites it dials
// direct) ask the network's DNS servers on the physical interface: the
// system's DNS is the tunnel's own now, which answers stand-in addresses.
func pinResolver(servers []netip.Addr) {
	networkDNS.Store(&servers)
	if len(servers) == 0 {
		return
	}
	var next atomic.Uint32
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := wire.NewDialer(3 * time.Second)
		s := servers[int(next.Add(1))%len(servers)]
		return d.DialContext(ctx, network, netip.AddrPortFrom(s, 53).String())
	}}
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
