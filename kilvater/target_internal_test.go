package kilvater

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// A key holder must not reach the server's own loopback services (or its LAN)
// unless the operator turned AllowPrivate on.
func TestTCPRefusesPrivateTargetByDefault(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
			accepted <- struct{}{}
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	for _, target := range []string{ln.Addr().String(), "localhost:" + port} {
		var down bytes.Buffer
		upR, upW := io.Pipe()
		upW.Close()
		(&Server{}).tcp(context.Background(), target, upR, &down, nil)

		typ, body, err := ReadFrame(&down, nil)
		if err != nil || typ != FrameClose || len(body) != 1 || body[0] != 1 {
			t.Fatalf("%s: want CLOSE(1), got type=%d body=%v err=%v", target, typ, body, err)
		}
	}
	select {
	case <-accepted:
		t.Fatal("server dialed a loopback target")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestPublicOnly(t *testing.T) {
	for addr, want := range map[string]bool{
		"1.1.1.1":          true,
		"2606:4700::1111":  true,
		"127.0.0.1":        false,
		"::1":              false,
		"10.1.2.3":         false,
		"172.16.0.1":       false,
		"192.168.1.1":      false,
		"169.254.169.254":  false,
		"100.64.0.1":       false,
		"0.0.0.0":          false,
		"fe80::1":          false,
		"fd00::1":          false,
		"::ffff:127.0.0.1": false,
		"224.0.0.1":        false,
	} {
		if got := publicOnly(netip.MustParseAddr(addr)); got != want {
			t.Errorf("publicOnly(%s) = %v, want %v", addr, got, want)
		}
	}
}
