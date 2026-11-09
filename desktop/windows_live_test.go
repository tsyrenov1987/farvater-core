//go:build windows && windowslive

package desktop

import (
	"strings"
	"testing"
)

// routes lists the routes to the private and tunnel prefixes.
func routes(t *testing.T) string {
	t.Helper()
	out, err := run("powershell", "-NoProfile", "-Command",
		"Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Where-Object { $_.DestinationPrefix -in '10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','0.0.0.0/1','128.0.0.0/1' } | ForEach-Object { $_.DestinationPrefix + ' ' + $_.NextHop + ' ' + $_.InterfaceIndex }")
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	return out
}

func fwRule() string {
	out, _ := run("netsh", "advfirewall", "firewall", "show", "rule", "name="+fwDNSRule)
	return out
}

func checkUp(t *testing.T, idx, hop string) {
	t.Helper()
	got := routes(t)
	t.Logf("routes while up:\n%s", got)
	for _, p := range privateRanges {
		if !strings.Contains(got, p+" "+hop+" "+idx) {
			t.Errorf("%s is not on the physical interface", p)
		}
	}
	for _, p := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if !strings.Contains(got, p+" ") {
			t.Errorf("%s missing", p)
		}
	}
	if !strings.Contains(fwRule(), fwDNSRule) {
		t.Error("firewall rule missing")
	}
}

func checkGone(t *testing.T) {
	t.Helper()
	got := routes(t)
	for _, p := range privateRanges {
		if strings.Contains(got, p) {
			t.Errorf("%s left behind: %s", p, got)
		}
	}
	if strings.Contains(fwRule(), "Enabled") {
		t.Errorf("firewall rule left behind")
	}
}

func TestLiveUpDownOff(t *testing.T) {
	out, err := run("powershell", "-NoProfile", "-Command", defaultRouteCmd)
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	f := strings.Fields(out)
	t.Logf("default route: %v", f)
	idx, hop := f[0], f[1]

	s, err := Up(Options{Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	checkUp(t, idx, hop)
	s.Down()
	checkGone(t)

	// A run that did not clean up: `off` works from state.json alone.
	s, err = Up(Options{Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	checkUp(t, idx, hop)
	if err := Off(); err != nil {
		t.Fatal(err)
	}
	checkGone(t)
	s.state = saved{}
	s.Down()
}
