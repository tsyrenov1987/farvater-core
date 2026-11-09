package desktop

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/tsyrenov1987/farvater-core/switchboard"
	"github.com/tsyrenov1987/farvater-core/wire"
)

// StateDir keeps what Down (or `off` after a crash) puts back.
const StateDir = "/Library/Application Support/Farvater"

const (
	pfAnchor  = "com.apple/farvater" // /etc/pf.conf loads com.apple/* anchors
	ipBoundIf = 25                   // IP_BOUND_IF
	v6BoundIf = 125                  // IPV6_BOUND_IF
)

type saved struct {
	DNS     map[string][]string `json:"dns"` // network service → servers ("Empty" = DHCP)
	PfToken string              `json:"pf_token,omitempty"`
	Scoped  [][]string          `json:"scoped,omitempty"` // route commands that undo the interface-scoped defaults
}

// System is the tunnel and what was changed on the machine to route into it.
type System struct {
	dev   tun.Device
	name  string
	phys  string
	state saved
	logf  func(string, ...any)
	*tunPackets
}

// Up creates the tunnel, pins the core's sockets to the physical interface,
// routes all of IPv4 and IPv6 into the tunnel and points the system's DNS
// at it.
func Up(o Options) (*System, error) {
	logf := o.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	out, err := run("route", "-n", "get", "default")
	if err != nil {
		return nil, fmt.Errorf("default route: %v %s", err, out)
	}
	m := regexp.MustCompile(`interface: (\S+)`).FindStringSubmatch(out)
	if m == nil || strings.HasPrefix(m[1], "utun") {
		return nil, errors.New("no physical default route (another VPN running?)")
	}
	phys := m[1]
	if rt, _ := run("netstat", "-rn", "-f", "inet"); rt != "" {
		for _, l := range strings.Split(rt, "\n") {
			f := strings.Fields(l)
			if len(f) < 4 || (f[0] != "0/1" && f[0] != "128.0/1" && f[0] != "default") {
				continue
			}
			for _, c := range f[3:] {
				if strings.HasPrefix(c, "utun") {
					return nil, fmt.Errorf("another VPN already routes all traffic (%s): turn it off first", c)
				}
			}
		}
	}
	ifc, err := net.InterfaceByName(phys)
	if err != nil {
		return nil, err
	}
	idx := ifc.Index
	wire.SocketControl = func(network, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if strings.HasSuffix(network, "6") {
				serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, v6BoundIf, idx)
			} else {
				serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIf, idx)
				if serr != nil { // a dual-stack socket
					serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, v6BoundIf, idx)
				}
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
	upstream := systemDNS()
	pinResolver(upstream)

	dev, err := tun.CreateTUN("utun", MTU)
	if err != nil {
		return nil, fmt.Errorf("utun: %v", err)
	}
	name, _ := dev.Name()
	s := &System{dev: dev, name: name, phys: phys, logf: logf, tunPackets: newTunPackets(dev)}
	fail := func(err error) (*System, error) { s.Down(); return nil, err }
	// The core's sockets are bound to the physical interface (IP_BOUND_IF). With
	// the tunnel's 0/1 and 128/1 in the table, such a socket finds no route
	// ("network is unreachable") unless the physical interface has a default
	// route of its own, scoped to it.
	s.scopedDefaults(phys, out)
	steps := [][]string{
		{"ifconfig", name, "inet", TunAddr, TunAddr, "netmask", "255.255.255.255", "mtu", fmt.Sprint(MTU), "up"},
		{"ifconfig", name, "inet6", TunAddr6, "prefixlen", "128"},
		{"route", "-q", "-n", "add", "-inet", "0.0.0.0/1", "-interface", name},
		{"route", "-q", "-n", "add", "-inet", "128.0.0.0/1", "-interface", name},
		{"route", "-q", "-n", "add", "-inet", DNSAddr + "/32", "-interface", name},
		{"route", "-q", "-n", "add", "-inet6", "::/1", "-interface", name},
		{"route", "-q", "-n", "add", "-inet6", "8000::/1", "-interface", name},
	}
	for _, st := range steps {
		if out, err := run(st[0], st[1:]...); err != nil {
			return fail(fmt.Errorf("%s: %v %s", strings.Join(st, " "), err, out))
		}
	}
	s.state.DNS = map[string][]string{}
	for _, svc := range services() {
		cur, _ := run("networksetup", "-getdnsservers", svc)
		var list []string
		for _, l := range strings.Split(cur, "\n") {
			if _, err := netip.ParseAddr(strings.TrimSpace(l)); err == nil {
				list = append(list, strings.TrimSpace(l))
			}
		}
		if len(list) == 0 {
			list = []string{"Empty"}
		}
		s.state.DNS[svc] = list
	}
	s.save() // before changing anything: a crash leaves what `off` restores
	for svc := range s.state.DNS {
		_, _ = run("networksetup", "-setdnsservers", svc, DNSAddr)
	}
	_, _ = run("dscacheutil", "-flushcache")
	_, _ = run("killall", "-HUP", "mDNSResponder")
	if o.KillSwitch {
		if err := s.killSwitch(o.Nodes, upstream); err != nil {
			return fail(fmt.Errorf("kill switch: %v", err))
		}
	}
	s.save()
	logf("tunnel %s up, core pinned to %s, dns %v", name, phys, upstream)
	return s, nil
}

// killSwitch loads a pf anchor that lets out only the tunnel, the local
// networks, the catalogue's servers, the network's DNS servers and the
// Russian ranges (the core's direct dials). Rules outlive the process: a
// crash leaves the machine offline rather than outside the tunnel.
func (s *System) killSwitch(nodes, dns []netip.Addr) error {
	ru := filepath.Join(StateDir, "ru4.txt")
	var b strings.Builder
	for _, p := range switchboard.RuPrefixes4() {
		b.WriteString(p.String() + "\n")
	}
	if err := os.WriteFile(ru, []byte(b.String()), 0o644); err != nil {
		return err
	}
	list := func(as []netip.Addr) string {
		var v []string
		for _, a := range as {
			v = append(v, a.String())
		}
		if len(v) == 0 {
			return "{ }"
		}
		return "{ " + strings.Join(v, ", ") + " }"
	}
	rules := fmt.Sprintf(`table <fv_nodes> const %s
table <fv_dns> const %s
table <fv_ru> const file "%s"
table <fv_lan> const { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255, fe80::/10, ff00::/8 }
pass quick on lo0 all
pass quick on %s all no state
pass out quick proto udp from any port 68 to any port 67
pass out quick inet6 proto icmp6 all
pass out quick to <fv_lan>
pass out quick to <fv_nodes>
pass out quick proto { udp, tcp } to <fv_dns> port 53
pass out quick inet to <fv_ru>
block drop out quick all
`, list(nodes), list(dns), ru, s.name)
	f := filepath.Join(StateDir, "pf.conf")
	if err := os.WriteFile(f, []byte(rules), 0o644); err != nil {
		return err
	}
	if out, err := run("pfctl", "-a", pfAnchor, "-f", f); err != nil {
		return fmt.Errorf("%v %s", err, out)
	}
	out, _ := run("pfctl", "-E")
	if m := regexp.MustCompile(`Token : (\d+)`).FindStringSubmatch(out); m != nil {
		s.state.PfToken = m[1]
	}
	return nil
}

// Down puts the machine back: DNS, kill switch, the tunnel (its routes go
// with it).
func (s *System) Down() {
	delScoped(s.state)
	if s.state.DNS != nil {
		restore(s.state)
	}
	if s.dev != nil {
		s.dev.Close()
	}
	_ = os.Remove(filepath.Join(StateDir, "state.json"))
}

// Off undoes what a run that did not clean up left (DNS, kill switch).
func Off() error {
	b, err := os.ReadFile(filepath.Join(StateDir, "state.json"))
	var st saved
	if err == nil {
		_ = json.Unmarshal(b, &st)
	}
	restore(st)
	_, _ = run("pfctl", "-a", pfAnchor, "-F", "all")
	return os.Remove(filepath.Join(StateDir, "state.json"))
}

// scopedDefaults gives phys its own default routes, IPv4 from the route
// table's reply (v4out) and IPv6 when the network has a router.
func (s *System) scopedDefaults(phys, v4out string) {
	add := func(fam, gw string) {
		args := []string{"-q", "-n", "add", fam, "default"}
		if gw != "" {
			args = append(args, gw)
		} else {
			args = append(args, "-interface", phys)
		}
		args = append(args, "-ifscope", phys)
		if _, err := run("route", args...); err == nil {
			del := append([]string{"-q", "-n", "delete", fam, "default"}, args[5:]...)
			s.state.Scoped = append(s.state.Scoped, del)
		}
	}
	gw := ""
	if m := regexp.MustCompile(`gateway: (\S+)`).FindStringSubmatch(v4out); m != nil {
		gw = m[1]
	}
	add("-inet", gw)
	if out, err := run("route", "-n", "get", "-inet6", "default"); err == nil {
		if m := regexp.MustCompile(`gateway: (\S+)`).FindStringSubmatch(out); m != nil {
			g := m[1]
			if !strings.Contains(g, "%") && strings.HasPrefix(g, "fe80") {
				g += "%" + phys
			}
			add("-inet6", g)
		}
	}
}

func delScoped(st saved) {
	for _, a := range st.Scoped {
		_, _ = run("route", a...)
	}
}

func restore(st saved) {
	delScoped(st)
	for svc, list := range st.DNS {
		_, _ = run("networksetup", append([]string{"-setdnsservers", svc}, list...)...)
	}
	_, _ = run("pfctl", "-a", pfAnchor, "-F", "all")
	if st.PfToken != "" {
		_, _ = run("pfctl", "-X", st.PfToken)
	}
	_, _ = run("dscacheutil", "-flushcache")
	_, _ = run("killall", "-HUP", "mDNSResponder")
}

func (s *System) save() {
	_ = os.MkdirAll(StateDir, 0o755)
	b, _ := json.Marshal(s.state)
	_ = os.WriteFile(filepath.Join(StateDir, "state.json"), b, 0o600)
}

// services lists the enabled network services ("Wi-Fi", "Ethernet").
func services() []string {
	out, _ := run("networksetup", "-listallnetworkservices")
	var v []string
	for i, l := range strings.Split(out, "\n") {
		if i == 0 || l == "" || strings.HasPrefix(l, "*") {
			continue
		}
		v = append(v, l)
	}
	return v
}

// systemDNS reads the resolvers the network gave, before the tunnel takes
// the system's DNS over.
func systemDNS() []netip.Addr {
	out, _ := run("scutil", "--dns")
	seen := map[netip.Addr]bool{}
	var v []netip.Addr
	sc := bufio.NewScanner(strings.NewReader(out))
	re := regexp.MustCompile(`nameserver\[\d+\]\s*:\s*(\S+)`)
	for sc.Scan() {
		if m := re.FindStringSubmatch(sc.Text()); m != nil {
			if a, err := netip.ParseAddr(m[1]); err == nil && a.Is4() && !seen[a] && a.String() != DNSAddr {
				seen[a] = true
				v = append(v, a)
			}
		}
		if strings.HasPrefix(sc.Text(), "DNS configuration (for scoped") {
			break
		}
	}
	return v
}
