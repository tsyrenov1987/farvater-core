package switchboard

import (
	"net/netip"
	"testing"
)

func TestRuPrefixes4CoverRanges(t *testing.T) {
	ps := RuPrefixes4()
	if len(ps) < len(ru4)/8 {
		t.Fatalf("%d prefixes for %d ranges", len(ps), len(ru4)/8)
	}
	for _, p := range ps {
		if !isRuIP(p.Addr()) || !isRuIP(lastOf(p)) {
			t.Fatalf("%v is not wholly Russian", p)
		}
	}
	for _, a := range []string{"8.8.8.8", "1.1.1.1"} {
		ip := netip.MustParseAddr(a)
		for _, p := range ps {
			if p.Contains(ip) {
				t.Fatalf("%s in %v", a, p)
			}
		}
	}
}

func lastOf(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= uint32(1)<<(32-p.Bits()) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
