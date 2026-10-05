package switchboard

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/catalogue"
)

func TestRoutable(t *testing.T) {
	for host, want := range map[string]bool{
		"example.com":     true,
		"1.1.1.1":         true,
		"2606:4700::1111": true,
		"198.18.0.2":      false, // the apps' mapped-DNS address
		"198.19.255.1":    false,
		"100.64.0.7":      false, // mapped-DNS pool / CGNAT
		"10.0.0.1":        false,
		"172.16.5.4":      false,
		"192.168.1.1":     false,
		"127.0.0.1":       false,
		"169.254.1.1":     false,
		"0.0.0.0":         false,
		"224.0.0.251":     false,
		"::1":             false,
		"fe80::1":         false,
		"fc00::1":         false,
		"::ffff:10.0.0.1": false,
		"::ffff:8.8.8.8":  true,
	} {
		if got := routable(host); got != want {
			t.Errorf("routable(%q) = %v, want %v", host, got, want)
		}
	}
}

// A flow to the tunnel's own DNS address is refused before any dial and
// leaves no receipt against the path.
func TestRefusesUnroutableWithoutReceipt(t *testing.T) {
	cat, err := catalogue.Parse([]byte("vless://00000000-0000-0000-0000-000000000000@127.0.0.1:9?security=none&type=tcp#dead"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(DefaultConfig(), cat)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.serveListener(ctx, ln) }()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte{5, 1, 0, 1, 198, 18, 0, 2, 0x03, 0x55}); err != nil { // 198.18.0.2:853
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 2 {
		t.Fatalf("reply status %d, want 2 (not allowed)", reply[1])
	}
	time.Sleep(200 * time.Millisecond)
	if n := len(s.Receipts()); n != 0 {
		t.Fatalf("%d receipts filed for a refused flow", n)
	}
}
