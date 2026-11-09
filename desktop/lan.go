package desktop

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// privateRanges stay on the physical network. A path's exit cannot reach them
// (switchboard's routable refuses them), so a private address the computer
// reaches through its gateway, such as another subnet of an office or a
// provider's internal host, would go into the tunnel and die there.
var privateRanges = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

// parseDefaultRoute reads "<interface index> <next hop>". The next hop comes
// back empty when it is missing or malformed: the tunnel still works then,
// only the private ranges stay in it.
func parseDefaultRoute(out string) (int, string, error) {
	f := strings.Fields(out)
	if len(f) == 0 {
		return 0, "", fmt.Errorf("no default route in %q", out)
	}
	idx, err := strconv.Atoi(f[0])
	if err != nil || idx <= 0 {
		return 0, "", fmt.Errorf("no interface index in %q", out)
	}
	if len(f) > 1 {
		if a, err := netip.ParseAddr(f[1]); err == nil && a.Is4() {
			return idx, f[1], nil
		}
	}
	return idx, "", nil
}

// netshLANRoute is the netsh command that adds or deletes ("add", "delete")
// one private range on the physical interface. A next hop of 0.0.0.0 means an
// on-link default route (PPPoE and the like). store=active: the route is gone
// after a reboot whatever becomes of this program.
func netshLANRoute(verb, prefix string, idx int, hop string) []string {
	args := []string{"interface", "ipv4", verb, "route", "prefix=" + prefix, "interface=" + strconv.Itoa(idx)}
	if hop != "0.0.0.0" {
		args = append(args, "nexthop="+hop)
	}
	return append(args, "store=active")
}

var gatewayRE = regexp.MustCompile(`gateway: (\S+)`)

// routeTarget is the end of a macOS `route add` for a private range, from the
// reply of `route -n get default`: the gateway, or the interface when the
// reply names none that is an address (link#N on a point-to-point network).
func routeTarget(v4out, phys string) []string {
	if m := gatewayRE.FindStringSubmatch(v4out); m != nil {
		if a, err := netip.ParseAddr(m[1]); err == nil && a.Is4() {
			return []string{m[1]}
		}
	}
	return []string{"-interface", phys}
}
