//go:build windows

package desktop

import (
	"net/netip"
	"testing"
)

func TestComplement(t *testing.T) {
	got := complement([]netip.Addr{netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("8.8.8.8")})
	want := "0.0.0.0-8.8.8.7,8.8.8.9-198.18.0.1,198.18.0.3-255.255.255.255"
	if got != want {
		t.Fatalf("%s", got)
	}
}
