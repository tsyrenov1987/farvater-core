package wire

import (
	"context"
	"net"
	"testing"
	"time"
)

// A server given by name: the address that connected is dialled straight the
// next time, with no lookup; one that stops answering is dropped and the name
// is asked again; a new network forgets them all.
func TestANamedServersAddressIsKeptBetweenDials(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	ForgetAddrs()
	defer ForgetAddrs()

	c, err := dialTCP(context.Background(), "localhost", port)
	if err != nil {
		t.Skipf("localhost does not resolve to the listener here: %v", err)
	}
	c.Close()
	if got := addrs.get("localhost"); got != "127.0.0.1" {
		t.Fatalf("kept %q for localhost, want the address that connected", got)
	}

	// A name no DNS knows connects while its address is kept: no lookup is made.
	addrs.put("kept.invalid", "127.0.0.1")
	c, err = dialTCP(context.Background(), "kept.invalid", port)
	if err != nil {
		t.Fatalf("a kept address was not dialled straight: %v", err)
	}
	c.Close()

	// The kept address refuses: it is dropped, and the name is asked again.
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadPort := dead.Addr().(*net.TCPAddr).Port
	dead.Close()
	if _, err := dialTCP(context.Background(), "kept.invalid", deadPort); err == nil {
		t.Fatal("setup: a closed port connected")
	}
	if got := addrs.get("kept.invalid"); got != "" {
		t.Fatalf("an address that refused is still kept: %q", got)
	}

	// Kept addresses age out, and a new network forgets them.
	now := time.Now()
	addrs.now = func() time.Time { return now }
	defer func() { addrs.now = time.Now }()
	addrs.put("a.invalid", "127.0.0.1")
	now = now.Add(addrKept)
	if got := addrs.get("a.invalid"); got != "" {
		t.Fatalf("an address is still kept after %v: %q", addrKept, got)
	}
	addrs.put("b.invalid", "127.0.0.1")
	ForgetAddrs()
	if got := addrs.get("b.invalid"); got != "" {
		t.Fatalf("an address outlived the network change: %q", got)
	}
}
