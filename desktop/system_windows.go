package desktop

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/tsyrenov1987/farvater-core/wire"
)

// StateDir keeps what Down (or `off` after a crash) puts back.
var StateDir = filepath.Join(os.Getenv("ProgramData"), "Farvater")

const (
	tunName   = "Farvater"
	ipUnicast = 31 // IP_UNICAST_IF
	v6Unicast = 31 // IPV6_UNICAST_IF
	fwDNSRule = "Farvater DNS"

	// defaultRouteCmd prints "<interface index> <next hop>" of the default route.
	defaultRouteCmd = "$r = Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1; [string]$r.InterfaceIndex + ' ' + $r.NextHop"
)

type saved struct {
	Firewall bool       `json:"firewall"`
	LAN      [][]string `json:"lan,omitempty"` // netsh commands that undo the private-range routes
}

// System is the tunnel (Wintun; wintun.dll next to the program) and what was
// changed on the machine to route into it.
type System struct {
	dev   tun.Device
	state saved
	logf  func(string, ...any)
	*tunPackets
}

// Up creates the tunnel, pins the core's sockets to the physical interface,
// routes all of IPv4 and IPv6 into the tunnel, gives it the DNS and blocks
// DNS everywhere else (Windows asks every interface's servers otherwise).
func Up(o Options) (*System, error) {
	logf := o.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	out, err := run("powershell", "-NoProfile", "-Command", defaultRouteCmd)
	if err != nil {
		return nil, fmt.Errorf("default route: %v %s", err, out)
	}
	idx, hop, err := parseDefaultRoute(out)
	if err != nil {
		return nil, fmt.Errorf("default route: %v", err)
	}
	wire.SocketControl = func(network, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			h := syscall.Handle(fd)
			if strings.HasSuffix(network, "6") {
				serr = syscall.SetsockoptInt(h, syscall.IPPROTO_IPV6, v6Unicast, idx)
				return
			}
			var be [4]byte // IP_UNICAST_IF takes the index in network order
			binary.BigEndian.PutUint32(be[:], uint32(idx))
			serr = syscall.SetsockoptInt(h, syscall.IPPROTO_IP, ipUnicast, int(binary.NativeEndian.Uint32(be[:])))
		})
		if err != nil {
			return err
		}
		return serr
	}
	dnsOut, _ := run("powershell", "-NoProfile", "-Command",
		fmt.Sprintf("(Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex %d).ServerAddresses", idx))
	var upstream []netip.Addr
	for _, l := range strings.Fields(dnsOut) {
		if a, err := netip.ParseAddr(l); err == nil {
			upstream = append(upstream, a)
		}
	}
	pinResolver(upstream)

	dev, err := tun.CreateTUN(tunName, MTU)
	if err != nil {
		return nil, fmt.Errorf("wintun: %v", err)
	}
	s := &System{dev: dev, logf: logf, tunPackets: newTunPackets(dev)}
	fail := func(err error) (*System, error) { s.Down(); return nil, err }
	steps := [][]string{
		{"netsh", "interface", "ipv4", "set", "address", "name=" + tunName, "static", TunAddr, "255.255.255.255"},
		{"netsh", "interface", "ipv4", "set", "interface", tunName, "metric=1"},
		{"netsh", "interface", "ipv4", "set", "dnsservers", "name=" + tunName, "static", DNSAddr, "register=none", "validate=no"},
		{"netsh", "interface", "ipv4", "add", "route", "0.0.0.0/1", tunName, TunAddr, "metric=1"},
		{"netsh", "interface", "ipv4", "add", "route", "128.0.0.0/1", tunName, TunAddr, "metric=1"},
		{"netsh", "interface", "ipv4", "add", "route", DNSAddr + "/32", tunName, TunAddr, "metric=1"},
		{"netsh", "interface", "ipv6", "set", "address", tunName, TunAddr6},
		{"netsh", "interface", "ipv6", "add", "route", "::/1", tunName, "metric=1"},
		{"netsh", "interface", "ipv6", "add", "route", "8000::/1", tunName, "metric=1"},
	}
	for _, st := range steps {
		if out, err := run(st[0], st[1:]...); err != nil {
			return fail(fmt.Errorf("%s: %v %s", strings.Join(st, " "), err, out))
		}
	}
	s.lanRoutes(idx, hop)
	s.state.Firewall = true
	s.save()
	// DNS to anything but the tunnel's server and the network's own (the
	// core's lookups for Russian sites) is blocked.
	allow := append([]netip.Addr{netip.MustParseAddr(DNSAddr)}, upstream...)
	for _, proto := range []string{"UDP", "TCP"} {
		if out, err := run("netsh", "advfirewall", "firewall", "add", "rule", "name="+fwDNSRule, "dir=out", "action=block",
			"protocol="+proto, "remoteport=53", "remoteip="+complement(allow)); err != nil {
			return fail(fmt.Errorf("firewall: %v %s", err, out))
		}
	}
	if o.KillSwitch {
		logf("kill switch on Windows: routing only (no firewall allow-list yet)")
	}
	logf("tunnel %s up, core pinned to interface %d, dns %v", tunName, idx, upstream)
	return s, nil
}

// lanRoutes keeps the private ranges on the physical network (see
// privateRanges). A failure costs only those addresses, so it does not stop
// the connection.
func (s *System) lanRoutes(idx int, hop string) {
	if hop == "" {
		return
	}
	for _, p := range privateRanges {
		if _, err := run("netsh", netshLANRoute("add", p, idx, hop)...); err != nil {
			s.logf("private range %s stays in the tunnel: %v", p, err)
			continue
		}
		s.state.LAN = append(s.state.LAN, netshLANRoute("delete", p, idx, hop))
	}
}

func undoLAN(st saved) {
	for _, a := range st.LAN {
		_, _ = run("netsh", a...)
	}
}

// complement writes the IPv4 space less the given addresses as netsh ranges.
func complement(allow []netip.Addr) string {
	var xs []uint32
	for _, a := range allow {
		if a.Is4() {
			b := a.As4()
			xs = append(xs, binary.BigEndian.Uint32(b[:]))
		}
	}
	for i := range xs { // tiny list: insertion sort, dedupe below
		for j := i; j > 0 && xs[j] < xs[j-1]; j-- {
			xs[j], xs[j-1] = xs[j-1], xs[j]
		}
	}
	ip := func(v uint32) string {
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}).String()
	}
	var parts []string
	lo := uint64(0)
	for _, x := range xs {
		if uint64(x) > lo {
			parts = append(parts, ip(uint32(lo))+"-"+ip(x-1))
		}
		if uint64(x)+1 > lo {
			lo = uint64(x) + 1
		}
	}
	if lo <= 0xffffffff {
		parts = append(parts, ip(uint32(lo))+"-255.255.255.255")
	}
	return strings.Join(parts, ",")
}

// Down puts the machine back; the tunnel's own routes and DNS go with it.
func (s *System) Down() {
	if s.state.Firewall {
		_, _ = run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+fwDNSRule)
	}
	if s.dev != nil {
		s.dev.Close()
	}
	undoLAN(s.state)
	_ = os.Remove(filepath.Join(StateDir, "state.json"))
}

// Off undoes what a run that did not clean up left.
func Off() error {
	_, _ = run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+fwDNSRule)
	if b, err := os.ReadFile(filepath.Join(StateDir, "state.json")); err == nil {
		var st saved
		_ = json.Unmarshal(b, &st)
		undoLAN(st)
	}
	err := os.Remove(filepath.Join(StateDir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *System) save() {
	_ = os.MkdirAll(StateDir, 0o755)
	b, _ := json.Marshal(s.state)
	_ = os.WriteFile(filepath.Join(StateDir, "state.json"), b, 0o600)
}
