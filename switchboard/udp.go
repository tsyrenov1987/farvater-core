package switchboard

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/tsyrenov1987/farvater-core/wire"
)

// UDP (DESIGN §5). hev-socks5-tunnel opens one association per app socket and
// destination (socksFwdUDP) and frames every datagram, both ways, as
// [data length u16][header length u8][SOCKS5 address][data]. An association
// rides the leader, falls through the brain's order when a path cannot carry
// it, and files no receipts. UDP/443 is QUIC: refused, so apps fall back to
// TCP, where delivery is measured.

const (
	// hevUDPBuf holds a datagram and its address on the way back; a larger one
	// would end hev's session, so it is dropped here.
	hevUDPBuf = 1500
	udpIdle   = 2 * time.Minute // hev gives up on its own after 60 s
	udpTries  = 3               // paths one association dials before it gives up
	// An association that ends within udpEarly with no answer most likely met
	// a path that refuses UDP: the path goes to the back for udpBackFor.
	udpEarly   = 5 * time.Second
	udpBackFor = 10 * time.Minute
)

// datagram is one framed datagram from the app side.
type datagram struct {
	to   wire.Target
	name bool // hev sent the destination as a name (mapped DNS)
	data []byte
}

var errUDPFrame = errors.New("udp: bad frame")

func readDatagram(r io.Reader) (datagram, error) {
	var h [3]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return datagram{}, err
	}
	hl := int(h[2])
	if hl < 3+4 {
		return datagram{}, errUDPFrame
	}
	b := make([]byte, hl-3+int(binary.BigEndian.Uint16(h[:2])))
	if _, err := io.ReadFull(r, b); err != nil {
		return datagram{}, err
	}
	a := b[:hl-3]
	d := datagram{data: b[hl-3:]}
	switch {
	case a[0] == 1 && len(a) == 7:
		d.to.Host = netip.AddrFrom4([4]byte(a[1:5])).String()
	case a[0] == 4 && len(a) == 19:
		d.to.Host = netip.AddrFrom16([16]byte(a[1:17])).String()
	case a[0] == 3 && len(a) == 4+int(a[1]):
		d.to.Host, d.name = string(a[2:2+int(a[1])]), true
	default:
		return datagram{}, errUDPFrame
	}
	d.to.Port = int(binary.BigEndian.Uint16(a[len(a)-2:]))
	return d, nil
}

func addrLen(a netip.AddrPort) int {
	if a.Addr().Is4() {
		return 7
	}
	return 19
}

func writeDatagram(w io.Writer, from netip.AddrPort, data []byte) error {
	n := addrLen(from)
	b := make([]byte, 3+n+len(data))
	binary.BigEndian.PutUint16(b, uint16(len(data)))
	b[2] = byte(3 + n)
	if ip := from.Addr(); ip.Is4() {
		b[3] = 1
		a := ip.As4()
		copy(b[4:], a[:])
	} else {
		b[3] = 4
		a := ip.As16()
		copy(b[4:], a[:])
	}
	binary.BigEndian.PutUint16(b[1+n:], from.Port())
	copy(b[3+n:], data)
	_, err := w.Write(b)
	return err
}

// replyFrom is the address a reply goes back with. hev delivers the replies of
// a named destination from that destination whatever this says; otherwise from
// the address given, which must be an IP of the destination's family: the
// reply's own source when it is one, else the destination itself.
func replyFrom(src wire.Target, to wire.Target, name bool) netip.AddrPort {
	dst, err := netip.ParseAddr(to.Host)
	dst = dst.Unmap()
	if ip, perr := netip.ParseAddr(src.Host); perr == nil && src.Port > 0 {
		if ip = ip.Unmap(); name || (err == nil && ip.Is4() == dst.Is4()) {
			return netip.AddrPortFrom(ip, uint16(src.Port))
		}
	}
	if err == nil {
		return netip.AddrPortFrom(dst, uint16(to.Port))
	}
	return netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(to.Port))
}

// udpAssoc is one association; ps and the rest are set once it reaches a path.
type udpAssoc struct {
	s     *Switchboard
	ps    wire.PacketSession
	path  string
	to    wire.Target
	name  bool
	start time.Time

	last                 atomic.Int64 // ms of the last datagram either way
	up, down             atomic.Int64 // bytes
	answers, overHevSize atomic.Int64
}

// serveUDP runs one association once the SOCKS request is read.
func (s *Switchboard) serveUDP(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Time{})
	if err := replySocks5(c, 0); err != nil {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	a := &udpAssoc{s: s}
	a.last.Store(nowMs())
	go a.watch(ctx, cancel, c)
	for {
		d, err := readDatagram(c)
		if err != nil || d.to.Port == 443 || !routable(d.to.Host) {
			break
		}
		if a.ps == nil {
			if !s.openUDP(ctx, a, d) {
				break
			}
			go a.pumpDown(ctx, cancel, c)
		}
		a.last.Store(nowMs())
		a.up.Add(int64(len(d.data)))
		if err := a.ps.WritePacket(d.data, d.to); err != nil {
			a.pathEnded(ctx)
			break
		}
	}
	cancel() // before the session closes: its end is then not the path's doing
	if a.ps != nil {
		a.finish()
	}
}

// openUDP dials the first paths of the UDP order until one carries UDP. A path
// that looks like no HTTP is dialled only as the first try: it never stands in
// for one that failed.
func (s *Switchboard) openUDP(ctx context.Context, a *udpAssoc, d datagram) bool {
	tries := 0
	for _, id := range s.udpOrder() {
		pw, ok := s.wires[id].(wire.PacketWire)
		if !ok || (tries > 0 && s.infos[id].NotHTTP) {
			continue
		}
		if tries == udpTries {
			break
		}
		tries++
		if err := s.pace(ctx, id); err != nil {
			return false
		}
		dctx, cancel := context.WithTimeout(ctx, s.cfg.DialTimeout)
		ps, err := pw.DialPacket(dctx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return false
			}
			s.logf("udp %s: %v", id, err)
			continue
		}
		s.udp.Add(1)
		a.ps, a.path, a.to, a.name, a.start = ps, id, d.to, d.name, time.Now()
		return true
	}
	return false
}

// udpOrder is the brain's UDP order with the paths that recently refused UDP
// moved to the back, each part keeping its order.
func (s *Switchboard) udpOrder() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := nowMs()
	var front, back []string
	for _, id := range s.b.UDPOrder(now) {
		if s.udpBack[id] > now {
			back = append(back, id)
		} else {
			front = append(front, id)
		}
	}
	return append(front, back...)
}

// pumpDown writes the path's datagrams back to the app until either side ends.
func (a *udpAssoc) pumpDown(ctx context.Context, cancel context.CancelFunc, c net.Conn) {
	defer cancel()
	for {
		p, src, err := a.ps.ReadPacket()
		if err != nil {
			a.pathEnded(ctx)
			return
		}
		a.last.Store(nowMs())
		from := replyFrom(src, a.to, a.name)
		if len(p)+addrLen(from) > hevUDPBuf {
			a.overHevSize.Add(1)
			continue
		}
		if err := writeDatagram(c, from, p); err != nil {
			return
		}
		a.answers.Add(1)
		a.down.Add(int64(len(p)))
	}
}

// pathEnded is called when the path ended the association: if that came early
// and with no answer, the path most likely refuses UDP and goes to the back.
func (a *udpAssoc) pathEnded(ctx context.Context) {
	if ctx.Err() == nil && a.answers.Load() == 0 && time.Since(a.start) < udpEarly {
		a.s.mu.Lock()
		a.s.udpBack[a.path] = nowMs() + udpBackFor.Milliseconds()
		a.s.mu.Unlock()
	}
}

// watch closes the app side once the association ends, and ends one that
// carried nothing either way for udpIdle.
func (a *udpAssoc) watch(ctx context.Context, cancel context.CancelFunc, c net.Conn) {
	defer c.Close() // unblocks the app-side reader
	t := time.NewTicker(udpIdle / 4)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if nowMs()-a.last.Load() >= udpIdle.Milliseconds() {
				cancel()
				return
			}
		}
	}
}

func (a *udpAssoc) finish() {
	a.ps.Close()
	a.s.logf("udp %s dst=%s up=%d down=%d answers=%d over_hev=%d dur=%dms", a.path, a.to.Host, a.up.Load(), a.down.Load(), a.answers.Load(), a.overHevSize.Load(), time.Since(a.start).Milliseconds())
}
