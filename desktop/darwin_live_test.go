//go:build darwin && darwinlive

package desktop

import (
	"os"
	"strings"
	"testing"
)

// sudo go test -tags darwinlive ./desktop -run Live -v
// Changes the Mac's routes and DNS for a few seconds and puts them back.

func netstat4(t *testing.T) string {
	t.Helper()
	out, err := run("netstat", "-rn", "-f", "inet")
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	return out
}

// hasRoute: a line for dst whose interface column is ifc ("" = any).
func hasRoute(table, dst, ifc string) bool {
	for _, l := range strings.Split(table, "\n") {
		f := strings.Fields(l)
		if len(f) < 4 || f[0] != dst {
			continue
		}
		if ifc == "" {
			return true
		}
		for _, c := range f[3:] {
			if c == ifc {
				return true
			}
		}
	}
	return false
}

// private: the routes for the whole private ranges as netstat names them
// (10/8 is "10", 192.168/16 is "192.168").
func private(table string) string {
	var v []string
	for _, l := range strings.Split(table, "\n") {
		if f := strings.Fields(l); len(f) > 3 && (f[0] == "10" || f[0] == "172.16/12" || f[0] == "192.168") {
			v = append(v, f[0]+" "+f[1]+" "+f[3])
		}
	}
	return strings.Join(v, "\n")
}

func dnsOf(t *testing.T) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, svc := range services() {
		out, _ := run("networksetup", "-getdnsservers", svc)
		m[svc] = strings.Join(parseDNSServers(out), ",")
	}
	return m
}

func checkDarwinUp(t *testing.T, s *System, phys string) {
	t.Helper()
	table := netstat4(t)
	t.Logf("routes while up:\n%s", table)
	for _, p := range []string{"0/1", "128.0/1"} {
		if !hasRoute(table, p, s.name) {
			t.Errorf("%s is not on %s", p, s.name)
		}
	}
	if pinned.Load() == 0 {
		t.Error("sockets are not pinned")
	}
	// netstat's -I prints the interface's counters, not its routes: the
	// scoped default is the "default" line with the I flag on phys.
	scoped := false
	for _, l := range strings.Split(table, "\n") {
		if f := strings.Fields(l); len(f) >= 4 && f[0] == "default" && strings.Contains(f[2], "I") && f[3] == phys {
			scoped = true
		}
	}
	if !scoped {
		t.Errorf("no default route scoped to %s", phys)
	}
	for svc, d := range dnsOf(t) {
		if d != DNSAddr {
			t.Errorf("%s DNS is %s, want %s", svc, d, DNSAddr)
		}
	}
	if _, err := os.Stat(StateDir + "/state.json"); err != nil {
		t.Errorf("state.json: %v", err)
	}
}

func checkDarwinGone(t *testing.T, name string, dns map[string]string, lan string) {
	t.Helper()
	table := netstat4(t)
	for _, p := range []string{"0/1", "128.0/1"} {
		if hasRoute(table, p, name) {
			t.Errorf("%s left on %s", p, name)
		}
	}
	if got := private(table); got != lan {
		t.Errorf("private-range routes:\n%s\nwere:\n%s", got, lan)
	}
	if pinned.Load() != 0 {
		t.Error("sockets still pinned")
	}
	if got := dnsOf(t); len(got) != len(dns) {
		t.Errorf("DNS services: %v, was %v", got, dns)
	} else {
		for svc, d := range dns {
			if got[svc] != d {
				t.Errorf("%s DNS is %s, was %s", svc, got[svc], d)
			}
		}
	}
	if _, err := os.Stat(StateDir + "/state.json"); err == nil {
		t.Error("state.json left behind")
	}
}

func TestLiveUpDownOff(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	out, err := run("route", "-n", "get", "default")
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	phys, gw := parseRouteGet(out)
	t.Logf("default route: %s via %s", phys, gw)
	dns := dnsOf(t)
	lan := private(netstat4(t))
	t.Logf("DNS before: %v", dns)

	s, err := Up(Options{Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	checkDarwinUp(t, s, phys)
	s.Down()
	s.Down() // twice: the second does nothing
	checkDarwinGone(t, s.name, dns, lan)

	// A run that did not clean up: `off` works from state.json alone.
	s, err = Up(Options{Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	checkDarwinUp(t, s, phys)
	if err := Off(); err != nil {
		t.Fatal(err)
	}
	s.state = saved{}
	s.Down()
	checkDarwinGone(t, s.name, dns, lan)
	if err := Off(); err != nil { // nothing to undo
		t.Fatal(err)
	}
}

// The search domains typed into a network service count, read the way Up
// reads them.
func TestLiveMachineSuffixes(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	svcs := services()
	if len(svcs) == 0 {
		t.Skip("no network service")
	}
	svc := svcs[0]
	was, _ := run("networksetup", "-getsearchdomains", svc)
	t.Cleanup(func() {
		list := parseSearchDomains(was)
		if len(list) == 0 {
			list = []string{"Empty"}
		}
		_, _ = run("networksetup", append([]string{"-setsearchdomains", svc}, list...)...)
		networkSuffixes.Store(nil)
	})
	if out, err := run("networksetup", "-setsearchdomains", svc, "Office.Example.TEST", "corp2.example.test"); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	loadMachineSuffixes(t.Logf)
	t.Logf("suffixes: %v", *networkSuffixes.Load())
	if !DirectName("app.office.example.test") || !DirectName("dc.corp2.example.test") || DirectName("example.test") {
		t.Fatalf("suffixes read as %v", *networkSuffixes.Load())
	}
}
