package desktop

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseDefaultRoute(t *testing.T) {
	for _, c := range []struct {
		in, hop string
		idx     int
		bad     bool
	}{
		{in: "12 192.168.1.1\r\n", idx: 12, hop: "192.168.1.1"},
		{in: "7 0.0.0.0", idx: 7, hop: "0.0.0.0"},
		{in: "12", idx: 12},                // the old reply: the tunnel must still come up
		{in: "12 fe80::1", idx: 12},        // not IPv4: no private routes, still connected
		{in: "12 garbage", idx: 12},        //
		{in: "", bad: true},                // no default route at all
		{in: "  \r\n", bad: true},          //
		{in: "Get-NetRoute: x", bad: true}, // PowerShell's error text
		{in: "0 192.168.1.1", bad: true},   //
	} {
		idx, hop, err := parseDefaultRoute(c.in)
		if (err != nil) != c.bad || idx != c.idx || hop != c.hop {
			t.Errorf("%q: %d %q %v", c.in, idx, hop, err)
		}
	}
}

func TestNetshLANRoute(t *testing.T) {
	got := strings.Join(netshLANRoute("add", "10.0.0.0/8", 12, "192.168.1.1"), " ")
	if want := "interface ipv4 add route prefix=10.0.0.0/8 interface=12 nexthop=192.168.1.1 store=active"; got != want {
		t.Errorf("gateway: %s", got)
	}
	got = strings.Join(netshLANRoute("delete", "172.16.0.0/12", 7, "0.0.0.0"), " ")
	if want := "interface ipv4 delete route prefix=172.16.0.0/12 interface=7 store=active"; got != want {
		t.Errorf("on-link: %s", got)
	}
}

func TestRouteTarget(t *testing.T) {
	const reply = "   route to: default\ndestination: default\n    gateway: 192.168.1.1\n  interface: en0\n"
	if got := routeTarget(reply, "en0"); !reflect.DeepEqual(got, []string{"192.168.1.1"}) {
		t.Errorf("gateway: %v", got)
	}
	for _, r := range []string{"destination: default\n  interface: ppp0\n", "    gateway: link#14\n"} {
		if got := routeTarget(r, "ppp0"); !reflect.DeepEqual(got, []string{"-interface", "ppp0"}) {
			t.Errorf("%q: %v", r, got)
		}
	}
}

func TestPrivateRangesAvoidTunnelAddresses(t *testing.T) {
	for _, p := range privateRanges {
		for _, a := range []string{TunAddr, DNSAddr} {
			if strings.HasPrefix(a, strings.SplitN(p, ".", 2)[0]+".") {
				t.Errorf("%s overlaps %s", p, a)
			}
		}
	}
}
