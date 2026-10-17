package switchboard

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/catalogue"
)

// brokenOnce is a listener whose first Accept fails the way a socket iOS took
// from a suspended app does, and which really closes the port when it fails.
type brokenOnce struct {
	net.Listener
	failed atomic.Bool
}

func (b *brokenOnce) Accept() (net.Conn, error) {
	if b.failed.CompareAndSwap(false, true) {
		b.Listener.Close()
		return nil, errors.New("software caused connection abort")
	}
	return b.Listener.Accept()
}

// TestListenerComesBackOnTheSamePort: after the listening socket fails, the
// switchboard listens again on the same address, so a client that keeps the
// port (the Matrix SDK keeps its proxy URL for the whole session) connects.
func TestListenerComesBackOnTheSamePort(t *testing.T) {
	cat, err := catalogue.Parse([]byte("vless://00000000-0000-0000-0000-000000000000@127.0.0.1:9?security=tls&sni=example.com&type=tcp#dead"))
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
	addr := ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.serveListener(ctx, &brokenOnce{Listener: ln}) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("port %s never came back: %v", addr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not end with its context")
	}
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		c.Close()
		t.Fatal("port still open after the context ended")
	}
}
