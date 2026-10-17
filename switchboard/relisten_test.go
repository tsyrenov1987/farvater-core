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

// silentlyDead is a listener whose socket dies the way iOS takes it from a
// suspended app: the port refuses connections, yet the Accept that waits on
// it never returns until the listener itself is closed.
type silentlyDead struct {
	net.Listener
	died   atomic.Bool
	closed chan struct{}
	once   atomic.Bool
}

func (d *silentlyDead) Accept() (net.Conn, error) {
	if d.died.CompareAndSwap(false, true) {
		d.Listener.Close()
		<-d.closed
		return nil, errors.New("use of closed network connection")
	}
	return d.Listener.Accept()
}

func (d *silentlyDead) Close() error {
	if d.once.CompareAndSwap(false, true) {
		close(d.closed)
	}
	return d.Listener.Close()
}

// TestEnsureListeningRevivesASilentlyDeadPort: a socket taken without an
// Accept error stays refused by itself; EnsureListening brings the same port
// back.
func TestEnsureListeningRevivesASilentlyDeadPort(t *testing.T) {
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
	defer cancel()
	go func() { _ = s.serveListener(ctx, &silentlyDead{Listener: ln, closed: make(chan struct{})}) }()

	time.Sleep(300 * time.Millisecond)
	if takesConnections(addr) {
		t.Fatal("the dead port should refuse connections before EnsureListening")
	}
	if !s.EnsureListening(2 * time.Second) {
		t.Fatalf("port %s did not come back", addr)
	}
	if !takesConnections(addr) {
		t.Fatal("port refuses connections after EnsureListening")
	}
	if !s.EnsureListening(time.Second) {
		t.Fatal("a live port should pass the check")
	}
}
