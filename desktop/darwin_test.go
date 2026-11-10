//go:build darwin

package desktop

import (
	"fmt"
	"slices"
	"testing"
)

func TestParseServiceOrder(t *testing.T) {
	out := `An asterisk (*) denotes that a network service is disabled.
(1) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

(2) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(*) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en7)

(3) iPhone USB
(Hardware Port: iPhone USB, Device: en5)

(4) Some VPN
(Hardware Port: com.example.vpn, Device: )
`
	got := parseServiceOrder(out)
	want := map[string]string{"bridge0": "Thunderbolt Bridge", "en0": "Wi-Fi", "en5": "iPhone USB"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v", got)
	}
}

func TestParseDHCPDNS(t *testing.T) {
	out := "op = BOOTREPLY\nsubnet_mask (ip): 255.255.255.0\ndomain_name_server (ip_mult): {75.75.75.75, 75.75.76.76}\ndomain_name (string): hsd1.example.net\n"
	if got := fmt.Sprint(parseDHCPDNS(out)); got != "[75.75.75.75 75.75.76.76]" {
		t.Fatal(got)
	}
	if got := parseDHCPDNS(""); got != nil {
		t.Fatal(got)
	}
}

// The search list the user typed counts; DHCP's domain_name above does not.
func TestParseSearchDomains(t *testing.T) {
	if got := parseSearchDomains("There aren't any Search Domains set on Wi-Fi."); len(got) != 0 {
		t.Fatal(got)
	}
	if got := parseSearchDomains("office.example.test\ncorp2.example.test\n"); !slices.Equal(got, []string{"office.example.test", "corp2.example.test"}) {
		t.Fatal(got)
	}
}

func TestParseADDomain(t *testing.T) {
	out := "Active Directory Forest          = corp.example.test\nActive Directory Domain          = corp.example.test\nComputer Account                 = mac01$\n"
	if got := parseADDomain(out); !slices.Equal(got, []string{"corp.example.test"}) {
		t.Fatal(got)
	}
	if got := parseADDomain(""); got != nil {
		t.Fatal(got)
	}
}

func TestParseRouteGet(t *testing.T) {
	out := "   route to: default\ndestination: default\n       mask: default\n    gateway: 10.0.0.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n"
	if p, g := parseRouteGet(out); p != "en0" || g != "10.0.0.1" {
		t.Fatal(p, g)
	}
	if p, g := parseRouteGet("   route to: default\n  interface: ppp0\n"); p != "ppp0" || g != "" {
		t.Fatal(p, g)
	}
}

func TestParseDNSServers(t *testing.T) {
	if got := parseDNSServers("There aren't any DNS Servers set on Wi-Fi."); !slices.Equal(got, []string{"Empty"}) {
		t.Fatal(got)
	}
	if got := parseDNSServers("1.1.1.1\n2606:4700:4700::1111\n"); !slices.Equal(got, []string{"1.1.1.1", "2606:4700:4700::1111"}) {
		t.Fatal(got)
	}
}
