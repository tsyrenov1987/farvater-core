package switchboard

import (
	"context"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/catalogue"
)

func TestDirectNames(t *testing.T) {
	got := DirectNames("https://Online.Sberbank.ru/login?x=1, *.tbank.ru; .vtb.ru.\n" +
		"сбербанк.рф  1.2.3.4 [2001:db8::1]:443 ::ffff:5.6.7.8 user@mail.example.com:993 " +
		"localhost hello bad_name.ru sberbank.ru tbank.ru")
	want := []string{
		"online.sberbank.ru", "tbank.ru", "vtb.ru", "xn--80abap1arsf.xn--p1ai", "1.2.3.4", "2001:db8::1", "5.6.7.8",
		"mail.example.com", "sberbank.ru",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("DirectNames:\n got  %q\n want %q", got, want)
	}
	if got := DirectNames(" \n"); got == nil || len(got) != 0 {
		t.Fatalf("DirectNames(blank) = %#v, want an empty, non-nil list", got)
	}
}

func TestIsDirectCoversSubdomainsOnly(t *testing.T) {
	s := &Switchboard{cfg: Config{Direct: []string{"sberbank.ru", "1.2.3.4"}}}
	for host, want := range map[string]bool{
		"sberbank.ru":         true,
		"online.sberbank.ru":  true,
		"ONLINE.Sberbank.RU.": true,
		"notsberbank.ru":      false,
		"sberbank.ru.evil.io": false,
		"1.2.3.4":             true,
		"::ffff:1.2.3.4":      true,
		"1.2.3.40":            false,
	} {
		if got := s.isDirect(host); got != want {
			t.Errorf("isDirect(%q) = %v, want %v", host, got, want)
		}
	}
	if (&Switchboard{}).isDirect("sberbank.ru") {
		t.Error("no Direct names, yet a host went direct")
	}
}

// directBoard serves SOCKS5 over a catalogue whose only path is dead, so a
// flow that touched it would leave a receipt.
func directBoard(t *testing.T, direct ...string) (*Switchboard, string) {
	t.Helper()
	cat, err := catalogue.Parse([]byte("vless://00000000-0000-0000-0000-000000000000@127.0.0.1:9?security=tls&sni=example.com&type=tcp#dead"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Direct = direct
	s, err := New(cfg, cat)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.serveListener(ctx, ln) }()
	return s, ln.Addr().String()
}

// socksTo asks the switchboard at addr for host:port by name and returns the
// connection and the reply status.
func socksTo(t *testing.T, addr, host string, port int) (net.Conn, byte) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	return c, reply[1]
}

func TestDirectFlowGoesAroundThePaths(t *testing.T) {
	site, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer site.Close()
	// The site answers only once the app has finished sending: the app's
	// half-close has to reach it.
	go func() {
		c, err := site.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		got, _ := io.ReadAll(c)
		_, _ = c.Write(append([]byte("got:"), got...))
	}()
	s, addr := directBoard(t, "localhost")
	c, status := socksTo(t, addr, "localhost", site.Addr().(*net.TCPAddr).Port)
	if status != 0 {
		t.Fatalf("reply status %d, want 0", status)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = c.(*net.TCPConn).CloseWrite()
	answer, err := io.ReadAll(c)
	if err != nil || string(answer) != "got:ping" {
		t.Fatalf("answer %q, %v; want \"got:ping\"", answer, err)
	}
	st := s.Status()
	if st.Direct != 1 || st.Flows != 0 || len(st.Recent) != 0 {
		t.Fatalf("direct=%d flows=%d receipts=%d; want 1, 0, 0", st.Direct, st.Flows, len(st.Recent))
	}
}

func TestDirectFlowToAClosedPortIsRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	s, addr := directBoard(t, "localhost")
	if _, status := socksTo(t, addr, "localhost", port); status != 4 {
		t.Fatalf("reply status %d, want 4 (host unreachable)", status)
	}
	if st := s.Status(); st.Direct != 0 || len(st.Recent) != 0 {
		t.Fatalf("direct=%d receipts=%d; want 0, 0", st.Direct, len(st.Recent))
	}
}
