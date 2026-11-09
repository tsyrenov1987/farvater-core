package desktop

import (
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func suffixes(t *testing.T, s ...string) {
	t.Helper()
	setNetworkSuffixes(s)
	t.Cleanup(func() { networkSuffixes.Store(nil) })
}

func TestDirectName(t *testing.T) {
	suffixes(t, " Corp.Example.COM. ", "", ".")
	for host, want := range map[string]bool{
		"yastatic.net":          true,
		"avatars.yastatic.net":  true,
		"SUN9-1.USERAPI.COM.":   true,
		"vk.me":                 true,
		"fileserver":            true,
		"printer.lan":           true,
		"dc1.corp":              true,
		"nas.home.arpa":         true,
		"app.corp.example.com":  true,
		"corp.example.com":      true,
		"":                      false,
		"notyastatic.net":       false,
		"yastatic.net.evil.org": false,
		"example.com":           false,
		"other.example.com":     false,
		"youtube.com":           false,
		"lan.example.org":       false,
	} {
		if got := DirectName(host); got != want {
			t.Errorf("DirectName(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestServiceNamesLoaded(t *testing.T) {
	const fromTheList = 163
	const internal = 8
	if len(directZones) != fromTheList+internal {
		t.Fatalf("%d zones, want %d", len(directZones), fromTheList+internal)
	}
}

func query(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 77, RecursionDesired: true})
	if b.StartQuestions() != nil {
		t.Fatal("start")
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	q, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func answers(t *testing.T, out []byte) int {
	t.Helper()
	var p dnsmessage.Parser
	if _, err := p.Start(out); err != nil {
		t.Fatal(err)
	}
	if _, err := p.AllQuestions(); err != nil {
		t.Fatal(err)
	}
	a, err := p.AllAnswers()
	if err != nil {
		t.Fatal(err)
	}
	return len(a)
}

func TestLocalNamesMapOnlyUnderTheMachinesDomain(t *testing.T) {
	m := newMapDNS()
	if n := answers(t, m.answer(query(t, "printer.local.", dnsmessage.TypeA))); n != 0 {
		t.Fatalf("a .local name off the domain mapped: %d answers", n)
	}
	suffixes(t, "corp.local")
	if n := answers(t, m.answer(query(t, "dc1.corp.local.", dnsmessage.TypeA))); n != 1 {
		t.Fatalf("a name of the machine's domain: %d answers, want 1", n)
	}
	if n := answers(t, m.answer(query(t, "printer.local.", dnsmessage.TypeA))); n != 0 {
		t.Fatalf("another .local name mapped: %d answers", n)
	}
}

func TestOnlyTheDomainsOtherRecordsLeaveTheMachine(t *testing.T) {
	suffixes(t, "corp.example")
	m := newMapDNS()
	asked := 0
	real := []byte("real answer")
	m.forward = func([]byte) []byte { asked++; return real }

	srv := query(t, "_ldap._tcp.dc._msdcs.corp.example.", dnsmessage.TypeSRV)
	if got := m.answer(srv); string(got) != string(real) || asked != 1 {
		t.Fatalf("the domain's SRV: asked %d, got %q", asked, got)
	}
	for _, q := range [][]byte{
		query(t, "dc1.corp.example.", dnsmessage.TypeA),
		query(t, "dc1.corp.example.", dnsmessage.TypeAAAA),
		query(t, "_sip._tcp.example.com.", dnsmessage.TypeSRV),
	} {
		asked = 0
		if got := m.answer(q); string(got) == string(real) || asked != 0 {
			t.Fatalf("query left the machine: asked %d", asked)
		}
	}

	m.forward = func([]byte) []byte { return nil }
	if n := answers(t, m.answer(srv)); n != 0 {
		t.Fatalf("no server answered: %d answers, want an empty reply", n)
	}
}

func TestAskServer(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		b := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			out := append([]byte{}, b[:n]...)
			if out[2] == 1 { // the test's marker: answer with another ID
				out[0]++
			}
			_, _ = pc.WriteTo(out, from)
		}
	}()
	to := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	to = netip.AddrPortFrom(to.Addr().Unmap(), to.Port())
	if got := askServer([]byte{7, 9, 0, 4}, to); string(got) != string([]byte{7, 9, 0, 4}) {
		t.Fatalf("got %v", got)
	}
	if got := askServer([]byte{7, 9, 1, 4}, to); got != nil {
		t.Fatalf("a reply with another ID was taken: %v", got)
	}
}
