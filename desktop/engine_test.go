package desktop

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
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
)

// osSide is a second stack standing in for the machine's apps: what it sends
// is what the tunnel device would read.
type osSide struct {
	st *stack.Stack
	ep *channel.Endpoint
	in chan []byte
}

func newOS(t *testing.T, ctx context.Context) *osSide {
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(256, MTU, "")
	if err := st.CreateNIC(1, ep); err != nil {
		t.Fatal(err)
	}
	st.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(netip.MustParseAddr(TunAddr).AsSlice()).WithPrefix()}, stack.AddressProperties{})
	st.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	o := &osSide{st: st, ep: ep, in: make(chan []byte, 256)}
	go func() { <-ctx.Done(); ep.Close(); st.Close() }()
	return o
}

func (o *osSide) ReadPacket(b []byte) (int, error) {
	pkt := o.ep.ReadContext(context.Background())
	if pkt == nil {
		return 0, io.EOF
	}
	defer pkt.DecRef()
	v := pkt.ToView()
	defer v.Release()
	return copy(b, v.AsSlice()), nil
}

func (o *osSide) WritePacket(b []byte) error {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), b...))})
	o.ep.InjectInbound(header.IPv4ProtocolNumber, pkt)
	pkt.DecRef()
	return nil
}

// fakeSwitchboard answers SOCKS5 like the switchboard and records what each
// CONNECT asked for; the connection echoes, prefixed with the target.
func fakeSwitchboard(t *testing.T, got chan<- string) Conns {
	return func(ctx context.Context, c net.Conn) {
		defer c.Close()
		r := bufio.NewReader(c)
		g := make([]byte, 3)
		io.ReadFull(r, g)
		c.Write([]byte{5, 2})
		h := make([]byte, 2)
		io.ReadFull(r, h)
		u := make([]byte, h[1])
		io.ReadFull(r, u)
		pl, _ := r.ReadByte()
		p := make([]byte, pl)
		io.ReadFull(r, p)
		if string(u) != "u" || string(p) != "p" {
			c.Write([]byte{1, 1})
			return
		}
		c.Write([]byte{1, 0})
		q := make([]byte, 4)
		io.ReadFull(r, q)
		var host string
		switch q[3] {
		case 1:
			a := make([]byte, 4)
			io.ReadFull(r, a)
			host = netip.AddrFrom4([4]byte(a)).String()
		case 3:
			l, _ := r.ReadByte()
			n := make([]byte, l)
			io.ReadFull(r, n)
			host = string(n)
		}
		pb := make([]byte, 2)
		io.ReadFull(r, pb)
		target := net.JoinHostPort(host, itoa(binary.BigEndian.Uint16(pb)))
		got <- target
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		c.Write([]byte(target + " " + line))
	}
}

func itoa(v uint16) string { return netip.AddrPortFrom(netip.IPv4Unspecified(), v).String()[8:] }

func TestEngineMappedNameAndAddress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	o := newOS(t, ctx)
	got := make(chan string, 4)
	if _, err := Start(ctx, o, fakeSwitchboard(t, got), "u", "p", t.Logf); err != nil {
		t.Fatal(err)
	}
	// The app asks the system DNS (the tunnel's) for a name.
	dc, err := gonet.DialUDP(o.st, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(netip.MustParseAddr(DNSAddr).AsSlice()), Port: 53}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("example.org."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	dc.SetDeadline(time.Now().Add(5 * time.Second))
	dc.Write(q)
	buf := make([]byte, 512)
	n, err := dc.Read(buf)
	if err != nil {
		t.Fatal("dns:", err)
	}
	var p dnsmessage.Parser
	if _, err := p.Start(buf[:n]); err != nil {
		t.Fatal(err)
	}
	p.SkipAllQuestions()
	ans, err := p.AnswerHeader()
	if err != nil {
		t.Fatal("no answer:", err)
	}
	ar, _ := p.AResource()
	ip := netip.AddrFrom4(ar.A)
	if ans.Type != dnsmessage.TypeA || !mapped.Contains(ip) {
		t.Fatalf("answer %v %v", ans.Type, ip)
	}
	// AAAA: empty.
	b = dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 8})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("example.org."), Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET})
	q, _ = b.Finish()
	dc.Write(q)
	n, _ = dc.Read(buf)
	h, _ := p.Start(buf[:n])
	p.SkipAllQuestions()
	if _, err := p.AnswerHeader(); err == nil || h.ID != 8 {
		t.Fatal("AAAA answered")
	}

	try := func(dst netip.Addr, want string) {
		c, err := gonet.DialContextTCP(ctx, o.st, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(dst.AsSlice()), Port: 443}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal("dial:", err)
		}
		defer c.Close()
		c.Write([]byte("hello\n"))
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line != want+" hello\n" {
			t.Fatalf("got %q", line)
		}
		if g := <-got; g != want {
			t.Fatalf("switchboard asked for %s", g)
		}
	}
	try(ip, "example.org:443")                                 // by name: ru-direct and exit DNS work
	try(netip.MustParseAddr("93.184.216.34"), "93.184.216.34:443") // an app's own address
	// A stand-in address nobody holds is refused.
	if c, err := gonet.DialContextTCP(ctx, o.st, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(netip.MustParseAddr("100.100.0.9").AsSlice()), Port: 443}, ipv4.ProtocolNumber); err == nil {
		c.Close()
		t.Fatal("stale mapped address connected")
	}
}

func TestMapDNSWraps(t *testing.T) {
	m := newMapDNS()
	m.next = mapSize - 2
	a := m.addr("a.example")
	b := m.addr("b.example")
	if a == b || !mapped.Contains(a) || !mapped.Contains(b) {
		t.Fatal(a, b)
	}
	if n, _ := m.name(b); n != "b.example" {
		t.Fatal(n)
	}
}
