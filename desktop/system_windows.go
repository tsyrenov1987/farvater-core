package desktop

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/tsyrenov1987/farvater-core/wire"
)

// toolPath: the system's own copy of a tool. The service runs as SYSTEM, and
// a folder in PATH that users can write to must not decide what it starts.
func toolPath(name string) string {
	dir, err := windows.GetSystemDirectory()
	if err != nil || filepath.IsAbs(name) {
		return name
	}
	if name == "powershell" {
		return filepath.Join(dir, "WindowsPowerShell", "v1.0", "powershell.exe")
	}
	return filepath.Join(dir, name+".exe")
}

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

// pinned is the physical interface the core's sockets leave by, 0 while no
// tunnel is up. A service outlives its tunnels, and the machine can move to
// another interface under one (Follow), so the control function reads it for
// each socket.
var pinned atomic.Int32

func init() {
	wire.SocketControl = func(network, _ string, c syscall.RawConn) error {
		idx := int(pinned.Load())
		if idx == 0 {
			return nil
		}
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
}

// System is the tunnel (Wintun; wintun.dll next to the program) and what was
// changed on the machine to route into it.
type System struct {
	dev  tun.Device
	logf func(string, ...any)
	*tunPackets

	mu    sync.Mutex // state, down: Down and Follow's re-pinning
	state saved
	down  bool
}

// Up creates the tunnel, pins the core's sockets to the physical interface,
// routes all of IPv4 and IPv6 into the tunnel, gives it the DNS and blocks
// DNS everywhere else (Windows asks every interface's servers otherwise).
func Up(o Options) (*System, error) {
	logf := o.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	idx, hop, err := defaultRoute()
	if err != nil {
		return nil, fmt.Errorf("default route: %v", err)
	}
	logf("up: default route via interface %d, next hop %q", idx, hop)
	pinned.Store(int32(idx))
	upstream := interfaceDNS(idx)
	pinResolver(upstream)
	loadMachineSuffixes(logf)
	logf("up: network dns %v; creating the Wintun adapter", upstream)

	dev, err := tun.CreateTUN(tunName, MTU)
	if err != nil {
		return nil, fmt.Errorf("wintun: %v", err)
	}
	logf("up: Wintun adapter ready; routing")
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
	if err := blockOtherDNS(upstream); err != nil {
		return fail(err)
	}
	if o.KillSwitch {
		logf("kill switch on Windows: routing only (no firewall allow-list yet)")
	}
	logf("tunnel %s up, core pinned to interface %d, dns %v", tunName, idx, upstream)
	return s, nil
}

// loadMachineSuffixes reads the machine's DNS suffixes from the registry,
// where Get-DnsClientGlobalSetting and the domain join keep them: no
// PowerShell or WMI, which stripped Windows builds break.
func loadMachineSuffixes(logf func(string, ...any)) {
	setNetworkSuffixes(registrySuffixes())
}

func registrySuffixes() []string {
	var out []string
	read := func(path string, names ...string) {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
		if err != nil {
			return
		}
		defer k.Close()
		for _, n := range names {
			if v, _, err := k.GetStringValue(n); err == nil {
				out = append(out, strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == ';' })...)
			}
		}
	}
	read(`SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, "SearchList")
	read(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, "SearchList", "Domain")
	return out
}

// interfaceDNS is what the interface resolves names with: the adapter's own
// list (GetAdaptersAddresses), PowerShell only when that has nothing.
func interfaceDNS(idx int) []netip.Addr {
	if up := adapterDNS(idx); len(up) > 0 {
		return up
	}
	out, _ := run("powershell", "-NoProfile", "-Command",
		fmt.Sprintf("(Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex %d).ServerAddresses", idx))
	var upstream []netip.Addr
	for _, l := range strings.Fields(out) {
		if a, err := netip.ParseAddr(l); err == nil {
			upstream = append(upstream, a)
		}
	}
	return upstream
}

func adapterDNS(idx int) []netip.Addr {
	size := uint32(16 << 10)
	for range 3 {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_INET, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST, 0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil
		}
		var up []netip.Addr
		for a := first; a != nil; a = a.Next {
			if int(a.IfIndex) != idx {
				continue
			}
			for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
				if ip, ok := netip.AddrFromSlice(d.Address.IP()); ok && ip.Unmap().Is4() {
					up = append(up, ip.Unmap())
				}
			}
		}
		return up
	}
	return nil
}

// defaultRoute is the IPv4 default route Windows uses: the lowest route metric
// plus interface metric (what Get-NetRoute sorted by), read from the IP
// helper. PowerShell is the fallback only, under run's time limit.
func defaultRoute() (int, string, error) {
	if idx, hop, err := nativeDefaultRoute(); err == nil {
		return idx, hop, nil
	}
	out, err := run("powershell", "-NoProfile", "-Command", defaultRouteCmd)
	if err != nil {
		return 0, "", fmt.Errorf("%v %s", err, out)
	}
	return parseDefaultRoute(out)
}

func nativeDefaultRoute() (int, string, error) {
	var t *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &t); err != nil {
		return 0, "", err
	}
	defer windows.FreeMibTable(unsafe.Pointer(t))
	type cand struct {
		idx       int
		hop       string
		metric    uint64
		connected bool
	}
	var cs []cand
	for _, r := range t.Rows() {
		if r.DestinationPrefix.PrefixLength != 0 || r.Loopback != 0 {
			continue
		}
		row := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: r.InterfaceLuid, InterfaceIndex: r.InterfaceIndex}
		ifMetric, connected := uint64(0), true
		if windows.GetIpInterfaceEntry(&row) == nil {
			ifMetric, connected = uint64(row.Metric), row.Connected != 0
		}
		b := *(*[4]byte)(unsafe.Pointer(&r.NextHop.Data[0]))
		cs = append(cs, cand{int(r.InterfaceIndex), netip.AddrFrom4(b).String(), uint64(r.Metric) + ifMetric, connected})
	}
	slices.SortStableFunc(cs, func(a, b cand) int {
		if a.connected != b.connected {
			if a.connected {
				return -1
			}
			return 1
		}
		return int(a.metric) - int(b.metric)
	})
	if len(cs) == 0 {
		return 0, "", errors.New("no IPv4 default route")
	}
	return cs[0].idx, cs[0].hop, nil
}

// blockOtherDNS blocks DNS to anything but the tunnel's server and the
// network's own (the core's lookups for Russian sites).
func blockOtherDNS(upstream []netip.Addr) error {
	allow := append([]netip.Addr{netip.MustParseAddr(DNSAddr)}, upstream...)
	for _, proto := range []string{"UDP", "TCP"} {
		if out, err := run("netsh", "advfirewall", "firewall", "add", "rule", "name="+fwDNSRule, "dir=out", "action=block",
			"protocol="+proto, "remoteport=53", "remoteip="+complement(allow)); err != nil {
			return fmt.Errorf("firewall: %v %s", err, out)
		}
	}
	return nil
}

// defaultRoutes says which IPv4 default routes the machine has now; "" when
// it has none. The tunnel's own are /1, so they are not in it.
func defaultRoutes() (string, error) {
	var t *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &t); err != nil {
		return "", err
	}
	defer windows.FreeMibTable(unsafe.Pointer(t))
	var out []string
	for _, r := range t.Rows() {
		if r.DestinationPrefix.PrefixLength == 0 {
			out = append(out, fmt.Sprintf("%d %08x %d", r.InterfaceIndex, r.NextHop.Data[0], r.Metric))
		}
	}
	slices.Sort(out)
	return strings.Join(out, ","), nil
}

// Follow keeps the core on the machine's network as it changes (Wi-Fi to a
// cable, a new Wi-Fi) until ctx ends, and reports each new network: the core's
// sockets, the DNS it asks and the private-range routes all belong to one
// network. With no default route at all it waits for the next one.
func (s *System) Follow(ctx context.Context, changed func(network string)) {
	last, _ := defaultRoutes()
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now, err := defaultRoutes()
		if err != nil || now == "" || now == last {
			continue
		}
		idx, hop, err := defaultRoute()
		if err != nil {
			continue
		}
		last = now
		if s.move(ctx, idx, hop) {
			changed(fmt.Sprintf("if%d/%s", idx, hop))
		}
	}
}

// move goes over to the interface; false when it is the one in use, or the
// tunnel is going down.
func (s *System) move(ctx context.Context, idx int, hop string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down || ctx.Err() != nil || int(pinned.Load()) == idx {
		return false
	}
	pinned.Store(int32(idx))
	upstream := interfaceDNS(idx)
	pinResolver(upstream)
	_, _ = run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+fwDNSRule)
	if err := blockOtherDNS(upstream); err != nil {
		s.logf("%v", err)
	}
	undoLAN(s.state)
	s.state.LAN = nil
	s.lanRoutes(idx, hop)
	s.save()
	s.logf("moved to interface %d, dns %v", idx, upstream)
	return true
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return
	}
	s.down = true
	pinned.Store(0)
	net.DefaultResolver = &net.Resolver{}
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
