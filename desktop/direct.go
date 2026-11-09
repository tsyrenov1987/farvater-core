package desktop

import (
	_ "embed"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tsyrenov1987/farvater-core/wire"
)

// A computer sends these straight to the network too, beyond the zones the
// switchboard knows (ru.go), and falls back to the paths the same way when a
// direct dial fails. The phones do not: an app there has its own lists.

//go:embed servicenames.txt
var serviceNamesFile string

// directZones are matched with their subdomains: the Russian services' names
// outside .ru (their pictures, video and APIs, servicenames.txt, the list the
// iOS client's "sites past the VPN" takes), and the names no public DNS holds,
// which only the computer's own network can answer.
var directZones = func() map[string]bool {
	z := map[string]bool{}
	for _, n := range strings.Fields(serviceNamesFile) {
		z[n] = true
	}
	for _, n := range []string{"lan", "corp", "internal", "intranet", "home", "local", "localdomain", "home.arpa"} {
		z[n] = true
	}
	return z
}()

// DirectName reports whether a name goes straight to the network: one of
// directZones, a name of one label (a machine on the local network) or a name
// under the computer's own DNS suffixes.
func DirectName(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return false
	}
	if !strings.Contains(host, ".") {
		return true
	}
	for s := host; ; {
		if directZones[s] {
			return true
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			return onNetwork(host)
		}
		s = s[i+1:]
	}
}

// networkSuffixes are the DNS suffixes set on the machine itself. What a
// network hands out by DHCP does not count: any Wi-Fi could then send a whole
// zone around the tunnel.
var networkSuffixes atomic.Pointer[[]string]

func setNetworkSuffixes(in []string) {
	var out []string
	for _, s := range in {
		if s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), "."); s != "" {
			out = append(out, s)
		}
	}
	networkSuffixes.Store(&out)
}

// onNetwork reports whether a lowercase name is under one of those suffixes.
func onNetwork(name string) bool {
	p := networkSuffixes.Load()
	if p == nil {
		return false
	}
	for _, s := range *p {
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}

// networkDNS are the servers of the network the computer is on.
var networkDNS atomic.Pointer[[]netip.Addr]

// askNetwork puts a DNS query to those servers; nil when none answers.
func askNetwork(q []byte) []byte {
	p := networkDNS.Load()
	if p == nil {
		return nil
	}
	for _, s := range *p {
		if out := askServer(q, netip.AddrPortFrom(s, 53)); out != nil {
			return out
		}
	}
	return nil
}

func askServer(q []byte, to netip.AddrPort) []byte {
	const wait = 2 * time.Second
	d := wire.NewDialer(wait)
	c, err := d.Dial("udp", to.String())
	if err != nil {
		return nil
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(wait))
	if _, err := c.Write(q); err != nil {
		return nil
	}
	b := make([]byte, 4096)
	n, err := c.Read(b)
	if err != nil || n < 2 || len(q) < 2 || b[0] != q[0] || b[1] != q[1] {
		return nil
	}
	return b[:n]
}
