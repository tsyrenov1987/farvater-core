package switchboard

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/wire"
)

func TestRussianNamesAndAddresses(t *testing.T) {
	for host, want := range map[string]bool{
		"sberbank.ru":              true,
		"ONLINE.Sberbank.RU.":      true,
		"gosuslugi.ru":             true,
		"xn--80abap1arsf.xn--p1ai": true, // сбербанк.рф
		"kremlin.su":               true,
		"vk.com":                   true,
		"sun9-1.userapi.vk.com":    true,
		"api.ipify.org":            true,
		"ifconfig.me":              true,
		"checkip.amazonaws.com":    true,
		"amazonaws.com":            false,
		"rutracker.org":            false,
		"guru":                     false,
		"evil.guru":                false,
		"ru.example.com":           false,
		"notvk.com":                false,
		"youtube.com":              false,
	} {
		if got := isRuName(host); got != want {
			t.Errorf("isRuName(%q) = %v, want %v", host, got, want)
		}
	}
	for ip, want := range map[string]bool{
		"77.88.8.8":            true, // Yandex DNS
		"87.250.250.242":       true, // ya.ru
		"95.213.4.1":           true, // Selectel
		"::ffff:77.88.8.8":     true,
		"2a02:6b8::feed:0ff":   true, // Yandex
		"8.8.8.8":              false,
		"1.1.1.1":              false,
		"104.16.1.1":           false,
		"2001:4860:4860::8888": false,
		"0.0.0.0":              false,
		"255.255.255.255":      false,
		"::":                   false,
	} {
		if got := isRuIP(netip.MustParseAddr(ip)); got != want {
			t.Errorf("isRuIP(%s) = %v, want %v", ip, got, want)
		}
	}
}

// The tables are sorted, merged pairs: a lookup at each pair's edges finds it,
// and one just outside does not (unless the neighbour starts there).
func TestRussianRangesAreSortedAndFound(t *testing.T) {
	for _, tc := range []struct {
		t     string
		width int
	}{{ru4, 4}, {ru6, 8}} {
		n := len(tc.t) / tc.width / 2
		if n < 1000 || len(tc.t)%(2*tc.width) != 0 {
			t.Fatalf("width %d: %d bytes, %d pairs", tc.width, len(tc.t), n)
		}
		at := func(i int) uint64 {
			if tc.width == 4 {
				return uint64(binary.BigEndian.Uint32([]byte(tc.t[i*4:])))
			}
			return binary.BigEndian.Uint64([]byte(tc.t[i*8:]))
		}
		for i := 0; i < n; i++ {
			lo, hi := at(2*i), at(2*i+1)
			if lo > hi || (i > 0 && lo <= at(2*i-1)+1) {
				t.Fatalf("width %d pair %d [%x, %x] not sorted and merged", tc.width, i, lo, hi)
			}
			if !inRanges(tc.t, tc.width, lo) || !inRanges(tc.t, tc.width, hi) || inRanges(tc.t, tc.width, hi+1) || (lo > 0 && inRanges(tc.t, tc.width, lo-1)) {
				t.Fatalf("width %d pair %d [%x, %x] edges", tc.width, i, lo, hi)
			}
		}
	}
}

// localhostIsRussian counts the name localhost as Russian for the test
// (loopback addresses are refused as unroutable, names are not).
func localhostIsRussian(t *testing.T) {
	old := ruNames
	t.Cleanup(func() { ruNames = old })
	ruNames = append(append([]string(nil), old...), "localhost")
}

func ruBoard(t *testing.T) (*Switchboard, string) {
	t.Helper()
	s, addr := directBoard(t)
	s.cfg.RuDirect = true
	return s, addr
}

// A Russian site goes around the paths; one whose direct dial fails is
// carried over the paths, now and for ruDirectFor after.
func TestRussianSiteGoesAroundThePathsOrOverThemWhenUnreachable(t *testing.T) {
	localhostIsRussian(t)
	site, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer site.Close()
	go func() {
		for {
			c, err := site.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("hi"))
			c.Close()
		}
	}()
	s, addr := ruBoard(t)
	c, status := socksTo(t, addr, "localhost", site.Addr().(*net.TCPAddr).Port)
	if b, err := io.ReadAll(c); status != 0 || err != nil || string(b) != "hi" {
		t.Fatalf("status %d, answer %q %v; want 0, \"hi\"", status, b, err)
	}
	if st := s.Status(); st.Direct != 1 || st.Flows != 0 || len(st.Recent) != 0 {
		t.Fatalf("direct=%d flows=%d receipts=%d; want 1, 0, 0", st.Direct, st.Flows, len(st.Recent))
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if _, status := socksTo(t, addr, "x.localhost", closed); status != 0 {
		t.Fatalf("unreachable Russian site: reply %d, want 0 (taken over the paths)", status)
	}
	waitFor(t, func() bool { return s.Status().Flows == 1 })
	if !s.ruDirect("localhost") || s.ruDirect("x.localhost") {
		t.Fatal("want only the site whose direct dial failed over the paths")
	}
	s.mu.Lock()
	s.ruFailed["x.localhost"] = nowMs() - 1
	s.mu.Unlock()
	if !s.ruDirect("x.localhost") {
		t.Fatal("the site still over the paths after its time")
	}
}

func TestRussianDirectSparesTheProbesAndCanBeOff(t *testing.T) {
	s, _ := ruBoard(t)
	s.probeHosts = []string{"speed.yandex.ru"}
	if s.ruDirect("speed.yandex.ru") || !s.ruDirect("yandex.ru") {
		t.Fatal("a probe's host went direct, or its parent did not")
	}
	s.cfg.RuDirect = false
	if s.ruDirect("yandex.ru") || s.ruDirect("77.88.8.8") {
		t.Fatal("RuDirect off, yet a Russian site went direct")
	}
}

// A UDP association to a Russian address goes over the device's own network
// and dials no path; replies come back from the destination.
func TestRussianUDPGoesAroundThePaths(t *testing.T) {
	localhostIsRussian(t)
	pc, err := net.ListenPacket("udp", ":0") // localhost may be ::1 or 127.0.0.1
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(append([]byte("re:"), b[:n]...), from)
		}
	}()
	s, addr, fakes := udpBoard(t)
	s.cfg.RuDirect = true
	c := associate(t, addr)
	port := pc.LocalAddr().(*net.UDPAddr).Port
	// As hev sends a mapped name: [len u16][header len u8][3, name len, name, port][data].
	f := []byte{0, 4, byte(3 + 4 + len("localhost")), 3, byte(len("localhost"))}
	f = append(f, "localhost"...)
	f = append(f, byte(port>>8), byte(port))
	if _, err := c.Write(append(f, "ping"...)); err != nil {
		t.Fatal(err)
	}
	d, err := readDatagram(c)
	if err != nil || d.to.Port != port || string(d.data) != "re:ping" {
		t.Fatalf("reply %+v %v, want re:ping from port %d", d, err, port)
	}
	for id, f := range fakes {
		if f.dials.Load() != 0 {
			t.Fatalf("path %s dialled for a Russian destination", id)
		}
	}
	if st := s.Status(); st.Direct != 1 || st.UDP != 0 {
		t.Fatalf("direct=%d udp=%d; want 1, 0", st.Direct, st.UDP)
	}
	// A foreign destination still rides the paths.
	c2 := associate(t, addr)
	send(t, c2, "1.1.1.1:53", []byte("x"))
	if d, err := readDatagram(c2); err != nil || d.to != (wire.Target{Host: "1.1.1.1", Port: 53}) {
		t.Fatalf("foreign reply %+v %v", d, err)
	}
	if s.Status().UDP != 1 {
		t.Fatal("foreign association not over a path")
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatal("timed out")
}
