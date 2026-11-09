// Package desktop runs Farvater on a computer: a system tunnel (utun on macOS,
// Wintun on Windows) whose packets a user-space TCP/IP stack (gVisor) turns
// into connections, handed to the switchboard in process. Nothing listens on a
// local proxy port another program could find or use; the core's own sockets
// are pinned to the physical interface (wire.SocketControl), every other
// packet of the machine — IPv4 and IPv6 — takes the tunnel.
package desktop

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Addresses inside the tunnel. The system's DNS server is DNSAddr: queries never
// leave the machine, names resolve at the exit (or on the device's own network
// for a Russian site), as on the phones (hev's mapped DNS).
const (
	TunAddr  = "198.18.0.1"
	DNSAddr  = "198.18.0.2"
	TunAddr6 = "fdfa::1"
	MTU      = 1500
)

// Packets is the tunnel device: one IP packet per call.
type Packets interface {
	ReadPacket(b []byte) (int, error)
	WritePacket(b []byte) error
}

// Conns opens one SOCKS5 conversation with the switchboard
// (switchboard.ServeConn on the far end of a pipe).
type Conns func(ctx context.Context, c net.Conn)

// Engine is a running stack.
type Engine struct {
	ctx        context.Context
	serve      Conns
	user, pass string
	st         *stack.Stack
	ep         *channel.Endpoint
	dns        *mapDNS
	logf       func(string, ...any)
}

// Start brings the stack up on dev until ctx ends.
func Start(ctx context.Context, dev Packets, serve Conns, user, pass string, logf func(string, ...any)) (*Engine, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(1024, MTU, "")
	if err := st.CreateNIC(1, ep); err != nil {
		return nil, errors.New(err.String())
	}
	st.SetPromiscuousMode(1, true)
	st.SetSpoofing(1, true)
	st.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	sack := tcpip.TCPSACKEnabled(true)
	st.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	e := &Engine{ctx: ctx, serve: serve, user: user, pass: pass, st: st, ep: ep, dns: newMapDNS(), logf: logf}
	st.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(st, 0, 4096, e.onTCP).HandlePacket)
	st.SetTransportProtocolHandler(udp.ProtocolNumber, udp.NewForwarder(st, e.onUDP).HandlePacket)
	go e.inbound(dev)
	go e.outbound(dev)
	go func() {
		<-ctx.Done()
		ep.Close()
		st.Close()
	}()
	return e, nil
}

func (e *Engine) inbound(dev Packets) {
	buf := make([]byte, 65535)
	for e.ctx.Err() == nil {
		n, err := dev.ReadPacket(buf)
		if err != nil {
			if e.ctx.Err() == nil {
				e.logf("tun read: %v", err)
				time.Sleep(50 * time.Millisecond)
			}
			continue
		}
		if n < 1 {
			continue
		}
		var proto tcpip.NetworkProtocolNumber
		switch buf[0] >> 4 {
		case 4:
			proto = header.IPv4ProtocolNumber
		case 6:
			proto = header.IPv6ProtocolNumber
		default:
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), buf[:n]...))})
		e.ep.InjectInbound(proto, pkt)
		pkt.DecRef()
	}
}

func (e *Engine) outbound(dev Packets) {
	for {
		pkt := e.ep.ReadContext(e.ctx)
		if pkt == nil {
			return
		}
		v := pkt.ToView()
		_ = dev.WritePacket(v.AsSlice())
		v.Release()
		pkt.DecRef()
	}
}

func addrOf(a tcpip.Address) netip.Addr {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return ip.Unmap()
}

// target is what the switchboard is asked for: the name behind a mapped
// address, or the address. ok is false for a mapped address nobody holds any
// more (an app that kept an answer past its life): such a flow is refused.
func (e *Engine) target(ip netip.Addr) (host string, name, ok bool) {
	if n, found := e.dns.name(ip); found {
		return n, true, true
	}
	if mapped.Contains(ip) {
		return "", false, false
	}
	return ip.String(), false, true
}

// onTCP takes an app's TCP connection. IPv6 is refused at once (no AAAA is
// ever answered, so only an app with an address of its own tries it, and it
// falls back to IPv4): an exit's IPv6 can be placed in a different country.
func (e *Engine) onTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst := addrOf(id.LocalAddress)
	host, _, ok := e.target(dst)
	if !dst.Is4() || !ok {
		r.Complete(true)
		return
	}
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	c := gonet.NewTCPConn(&wq, ep)
	go e.serveTCP(c, host, id.LocalPort)
}

func (e *Engine) serveTCP(c net.Conn, host string, port uint16) {
	s, err := e.open(socksConnect, host, port)
	if err != nil {
		c.Close()
		return
	}
	relay(c, s)
}

func (e *Engine) onUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	dst := addrOf(id.LocalAddress)
	if !dst.Is4() {
		return true // dropped: see onTCP
	}
	isDNS := dst == dnsAddr && id.LocalPort == 53
	host, name, ok := "", false, true
	if !isDNS {
		if host, name, ok = e.target(dst); !ok || id.LocalPort == 443 {
			return true // QUIC: refused, apps fall back to TCP (the switchboard would refuse it too)
		}
	}
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		return true
	}
	c := gonet.NewUDPConn(&wq, ep)
	if isDNS {
		go e.serveDNS(c)
	} else {
		go e.serveUDP(c, host, name, id.LocalPort)
	}
	return true
}

func (e *Engine) serveDNS(c *gonet.UDPConn) {
	defer c.Close()
	b := make([]byte, 4096)
	for {
		_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
		n, err := c.Read(b)
		if err != nil {
			return
		}
		if out := e.dns.answer(b[:n]); out != nil {
			_, _ = c.Write(out)
		}
	}
}

// serveUDP carries one app socket's datagrams to one destination as a
// switchboard UDP association (the framing hev uses, udp.go in switchboard).
func (e *Engine) serveUDP(c *gonet.UDPConn, host string, name bool, port uint16) {
	defer c.Close()
	s, err := e.open(socksFwdUDP, "0.0.0.0", 0)
	if err != nil {
		return
	}
	defer s.Close()
	addr := socksAddr(host, port)
	var last sync.Mutex
	seen := time.Now()
	touch := func() { last.Lock(); seen = time.Now(); last.Unlock() }
	go func() { // down: frames from the switchboard to the app
		defer c.Close()
		var h [3]byte
		for {
			if _, err := io.ReadFull(s, h[:]); err != nil {
				return
			}
			hl, dl := int(h[2]), int(binary.BigEndian.Uint16(h[:2]))
			if hl < 3 {
				return
			}
			b := make([]byte, hl-3+dl)
			if _, err := io.ReadFull(s, b); err != nil {
				return
			}
			touch()
			if _, err := c.Write(b[hl-3:]); err != nil {
				return
			}
		}
	}()
	b := make([]byte, 65535)
	for {
		_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := c.Read(b)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				last.Lock()
				idle := time.Since(seen)
				last.Unlock()
				if idle < 2*time.Minute {
					continue
				}
			}
			return
		}
		touch()
		f := make([]byte, 3+len(addr)+n)
		binary.BigEndian.PutUint16(f, uint16(n))
		f[2] = byte(3 + len(addr))
		copy(f[3:], addr)
		copy(f[3+len(addr):], b[:n])
		if _, err := s.Write(f); err != nil {
			return
		}
	}
}

const (
	socksConnect = 1
	socksFwdUDP  = 5
)

var (
	dnsAddr = netip.MustParseAddr(DNSAddr)
	mapped  = netip.MustParsePrefix("100.64.0.0/10")
)

// open runs the client side of a SOCKS5 conversation with the switchboard over
// an in-memory pipe and returns the pipe once the switchboard has answered.
func (e *Engine) open(cmd byte, host string, port uint16) (net.Conn, error) {
	a, b := net.Pipe()
	go e.serve(e.ctx, b)
	_ = a.SetDeadline(time.Now().Add(20 * time.Second))
	fail := func(err error) (net.Conn, error) { a.Close(); return nil, err }
	if _, err := a.Write([]byte{5, 1, 2}); err != nil {
		return fail(err)
	}
	var r [2]byte
	if _, err := io.ReadFull(a, r[:]); err != nil || r[1] != 2 {
		return fail(errors.New("socks: no auth"))
	}
	auth := append([]byte{1, byte(len(e.user))}, e.user...)
	auth = append(append(auth, byte(len(e.pass))), e.pass...)
	if _, err := a.Write(auth); err != nil {
		return fail(err)
	}
	if _, err := io.ReadFull(a, r[:]); err != nil || r[1] != 0 {
		return fail(errors.New("socks: auth refused"))
	}
	if _, err := a.Write(append([]byte{5, cmd, 0}, socksAddr(host, port)...)); err != nil {
		return fail(err)
	}
	var rep [10]byte // the switchboard always replies with an IPv4 address
	if _, err := io.ReadFull(a, rep[:]); err != nil {
		return fail(err)
	}
	if rep[1] != 0 {
		return fail(errors.New("socks: refused"))
	}
	_ = a.SetDeadline(time.Time{})
	return a, nil
}

// socksAddr is a SOCKS5 address: type, address, port.
func socksAddr(host string, port uint16) []byte {
	var b []byte
	if ip, err := netip.ParseAddr(host); err == nil && ip.Is4() {
		a := ip.As4()
		b = append([]byte{1}, a[:]...)
	} else if err == nil {
		a := ip.As16()
		b = append([]byte{4}, a[:]...)
	} else {
		b = append([]byte{3, byte(len(host))}, host...)
	}
	return binary.BigEndian.AppendUint16(b, port)
}

// relay copies both ways and closes both ends when either side is done.
func relay(x, y net.Conn) {
	var once sync.Once
	done := func() { once.Do(func() { x.Close(); y.Close() }) }
	go func() { _, _ = io.Copy(y, x); done() }()
	_, _ = io.Copy(x, y)
	done()
}
