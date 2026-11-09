package desktop

import (
	"net/netip"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

// mapDNS answers the system's DNS queries inside the tunnel, as hev's mapped
// DNS does on the phones: an A query gets an address from 100.64.0.0/10 that
// stands for the name, so the switchboard is asked for the name and it
// resolves at the exit (or, for a Russian site, on the device's own network).
// AAAA and every other type get an empty answer. The one query that leaves the
// machine is for the other records of the computer's own domain (a domain's
// controllers are found by SRV), and it goes to that network's own servers.
type mapDNS struct {
	mu      sync.Mutex
	byName  map[string]netip.Addr
	byIP    map[netip.Addr]string
	next    uint32
	forward func(q []byte) []byte
}

const mapSize = 1 << 22 // the /10, less network and broadcast

func newMapDNS() *mapDNS {
	return &mapDNS{byName: map[string]netip.Addr{}, byIP: map[netip.Addr]string{}, next: 1, forward: askNetwork}
}

func (m *mapDNS) name(ip netip.Addr) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.byIP[ip]
	return n, ok
}

func (m *mapDNS) addr(name string) netip.Addr {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ip, ok := m.byName[name]; ok {
		return ip
	}
	base := mapped.Addr().As4()
	v := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	v += m.next
	ip := netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	if m.next++; m.next >= mapSize-1 {
		m.next = 1
	}
	if old, ok := m.byIP[ip]; ok { // wrapped: the oldest name gives its address up
		delete(m.byName, old)
	}
	m.byIP[ip], m.byName[name] = name, ip
	return ip
}

// answer builds the reply to one query, or nil to drop it.
func (m *mapDNS) answer(q []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil || h.Response {
		return nil
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 {
		return nil
	}
	qq := qs[0]
	name := strings.TrimSuffix(strings.ToLower(qq.Name.String()), ".")
	if qq.Type != dnsmessage.TypeA && qq.Type != dnsmessage.TypeAAAA && onNetwork(name) {
		if out := m.forward(q); out != nil {
			return out
		}
	}
	rh := dnsmessage.Header{ID: h.ID, Response: true, OpCode: h.OpCode, RecursionDesired: h.RecursionDesired, RecursionAvailable: true}
	b := dnsmessage.NewBuilder(nil, rh)
	b.EnableCompression()
	if b.StartQuestions() != nil || b.Question(qq) != nil || b.StartAnswers() != nil {
		return nil
	}
	if qq.Type == dnsmessage.TypeA && qq.Class == dnsmessage.ClassINET {
		if name != "" && (!strings.HasSuffix(name, ".local") || onNetwork(name)) {
			ip := m.addr(name).As4()
			_ = b.AResource(dnsmessage.ResourceHeader{Name: qq.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: ip})
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}
