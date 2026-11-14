//go:build windows && windowslive

package desktop

import (
	"strings"
	"testing"
	"time"
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

// dnsPolicy is the name servers Windows applies to "." under the NRPT, "" when
// no rule covers it. The DNS client takes a moment to read the registry, so
// it asks again for a few seconds until ok says the answer is the one wanted.
func dnsPolicy(t *testing.T, ok func(string) bool) string {
	t.Helper()
	var p string
	for i := 0; i < 10; i++ {
		out, err := run("powershell", "-NoProfile", "-Command",
			"Get-DnsClientNrptPolicy | Where-Object { $_.Namespace -eq '.' } | ForEach-Object { $_.NameServers -join ';' }")
		if err != nil {
			t.Fatalf("%v %s", err, out)
		}
		if p = strings.TrimSpace(out); ok(p) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Logf("dns policy for every name: %q", p)
	return p
}

func checkUp(t *testing.T, idx, hop string) {
	t.Helper()
	viaTunnel := func(p string) bool { return strings.HasPrefix(p, DNSAddr+";") }
	if p := dnsPolicy(t, viaTunnel); !viaTunnel(p) {
		t.Errorf("dns policy for every name is %q, want the tunnel's server, then the network's", p)
	}
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
	if p := dnsPolicy(t, func(p string) bool { return p == "" }); p != "" {
		t.Errorf("dns policy left behind: %q", p)
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

// The machine's own search list counts, read the way Up reads it.
func TestLiveMachineSuffixes(t *testing.T) {
	const get = "(Get-DnsClientGlobalSetting).SuffixSearchList -join ','"
	was, err := run("powershell", "-NoProfile", "-Command", get)
	if err != nil {
		t.Fatalf("%v %s", err, was)
	}
	set := func(list string) {
		if out, err := run("powershell", "-NoProfile", "-Command", "Set-DnsClientGlobalSetting -SuffixSearchList @("+list+")"); err != nil {
			t.Fatalf("%v %s", err, out)
		}
	}
	t.Cleanup(func() {
		var quoted []string
		for _, s := range strings.Split(was, ",") {
			if s != "" {
				quoted = append(quoted, "'"+s+"'")
			}
		}
		set(strings.Join(quoted, ","))
		networkSuffixes.Store(nil)
	})
	set("'Office.Example.TEST','corp2.example.test'")
	loadMachineSuffixes(t.Logf)
	t.Logf("suffixes: %v", *networkSuffixes.Load())
	if !DirectName("app.office.example.test") || !DirectName("dc.corp2.example.test") || DirectName("example.test") {
		t.Fatalf("suffixes read as %v", *networkSuffixes.Load())
	}
}
