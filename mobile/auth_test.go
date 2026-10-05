package mobile

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestPortIsClosedToOtherApps: the SOCKS5 port Start opens on loopback is
// reachable by every app on the device. Probed the way a scanner probes it
// (no authentication) it must not proxy; with the session's credentials it
// must; and each Start must issue new credentials.
func TestPortIsClosedToOtherApps(t *testing.T) {
	port := freePort(t)
	const dead = "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:9?security=none&type=tcp#dead"
	if err := Start(dead, port, "test"); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte{5, 1, 0})
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if greet[1] != 0xff {
		t.Fatalf("no-auth greeting answered %v: the port is an open proxy", greet)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := socksConnect(ctx, addr, SocksUser(), "wrong", "198.18.0.2:853"); err == nil || !strings.Contains(err.Error(), "credentials refused") {
		t.Fatalf("wrong password: err = %v, want credentials refused", err)
	}
	// The right credentials get past authentication to the routing check,
	// which refuses this unroutable target with status 2.
	if _, err := socksConnect(ctx, addr, SocksUser(), SocksPass(), "198.18.0.2:853"); err == nil || !strings.Contains(err.Error(), "status 2") {
		t.Fatalf("session credentials: err = %v, want connect status 2", err)
	}

	first := SocksPass()
	if len(first) < 26 {
		t.Fatalf("password %q is too short", first)
	}
	Stop() // the old listener closes asynchronously; restart elsewhere, as the apps do
	if err := Start(dead, freePort(t), "test"); err != nil {
		t.Fatal(err)
	}
	if SocksPass() == first {
		t.Fatal("Start reused the previous session's password")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
