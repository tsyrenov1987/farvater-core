package wire

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

// door is a stand-in for the app's loopback SOCKS5 door: it admits user/pass,
// reports each CONNECT target, and then either refuses with reply or carries
// the flow to the target.
func door(t *testing.T, user, pass string, reply byte) (addr string, targets <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	seen := make(chan string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				target, ok := doorHandshake(c, user, pass)
				if !ok {
					return
				}
				seen <- target
				if reply != 0 {
					_, _ = c.Write([]byte{5, reply, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				out, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer out.Close()
				_, _ = c.Write([]byte{5, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34}) // an IPv6 bound address
				go func() { _, _ = io.Copy(out, c) }()
				_, _ = io.Copy(c, out)
			}()
		}
	}()
	return ln.Addr().String(), seen
}

func doorHandshake(c net.Conn, user, pass string) (string, bool) {
	h := make([]byte, 3)
	if _, err := io.ReadFull(c, h); err != nil || !bytes.Equal(h, []byte{5, 1, 2}) {
		_, _ = c.Write([]byte{5, 0xff})
		return "", false
	}
	_, _ = c.Write([]byte{5, 2})
	a := make([]byte, 2)
	if _, err := io.ReadFull(c, a); err != nil {
		return "", false
	}
	u := make([]byte, a[1]+1)
	if _, err := io.ReadFull(c, u); err != nil {
		return "", false
	}
	p := make([]byte, u[len(u)-1])
	if _, err := io.ReadFull(c, p); err != nil {
		return "", false
	}
	if string(u[:len(u)-1]) != user || string(p) != pass {
		_, _ = c.Write([]byte{1, 1})
		return "", false
	}
	_, _ = c.Write([]byte{1, 0})
	r := make([]byte, 4)
	if _, err := io.ReadFull(c, r); err != nil || r[1] != 1 {
		return "", false
	}
	var host string
	switch r[3] {
	case 1, 4:
		ip := make([]byte, 4)
		if r[3] == 4 {
			ip = make([]byte, 16)
		}
		if _, err := io.ReadFull(c, ip); err != nil {
			return "", false
		}
		a, _ := netip.AddrFromSlice(ip)
		host = a.String()
	case 3:
		n := make([]byte, 1)
		if _, err := io.ReadFull(c, n); err != nil {
			return "", false
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return "", false
		}
		host = string(name)
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(c, port); err != nil {
		return "", false
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port)))), true
}

func hostedOlc(t *testing.T) HostedWire {
	t.Helper()
	spec, err := ParseURI("olcrtc://wbstream?vp8channel@room-1#" + testOlcKey + "$o")
	if err != nil {
		t.Fatal(err)
	}
	w, err := Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	h, ok := w.(HostedWire)
	if !ok || !IsHosted(spec.Kind) || w.NeedsHandshake() {
		t.Fatalf("olcrtc must be a hosted wire with no handshake to pace: %T", w)
	}
	return h
}

// A hosted path is down until the app hands over its door, and down again
// once the app takes it back.
func TestHostedDownWithoutDoor(t *testing.T) {
	w := hostedOlc(t)
	if _, err := w.Dial(context.Background()); !errors.Is(err, ErrNotUp) || w.Up() {
		t.Fatalf("no door: up %v, dial %v; want ErrNotUp", w.Up(), err)
	}
	addr, _ := door(t, "u", "p", 0)
	w.SetEndpoint(Endpoint{Addr: addr, User: "u", Pass: "p"})
	if !w.Up() {
		t.Fatal("door handed over, still down")
	}
	w.SetEndpoint(Endpoint{})
	if _, err := w.Dial(context.Background()); !errors.Is(err, ErrNotUp) || w.Up() {
		t.Fatalf("door taken back: up %v, dial %v", w.Up(), err)
	}
}

// Through the door a flow carries both ways, and the door is asked for the
// app's target exactly, with the door's credentials.
func TestHostedFlow(t *testing.T) {
	w := hostedOlc(t)
	addr, targets := door(t, "user1", "pass1", 0)
	w.SetEndpoint(Endpoint{Addr: addr, User: "user1", Pass: "pass1"})
	flowEchoOver(t, w)
	if got := <-targets; got[:10] != "127.0.0.1:" {
		t.Fatalf("door asked for %q", got)
	}
	for _, tg := range []Target{{Host: "example.com", Port: 443}, {Host: "2001:db8::1", Port: 80}, {Host: "::ffff:192.0.2.1", Port: 8080}} {
		sess, err := w.Dial(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		go func() { _, _ = sess.Run(context.Background(), tg, nil, make(chan []byte), io.Discard, nopMeter{}) }()
		want := tg.String()
		if tg.Host == "::ffff:192.0.2.1" {
			want = "192.0.2.1:8080"
		}
		select {
		case got := <-targets:
			if got != want {
				t.Fatalf("door asked for %q, want %q", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("door never asked for %v", tg)
		}
		sess.Close()
	}
}

// A wrong password fails the dial; a refused CONNECT fails the flow before
// any byte, as an error.
func TestHostedRefusals(t *testing.T) {
	w := hostedOlc(t)
	addr, _ := door(t, "u", "p", 0)
	w.SetEndpoint(Endpoint{Addr: addr, User: "u", Pass: "wrong"})
	if _, err := w.Dial(context.Background()); err == nil {
		t.Fatal("wrong password: dial succeeded")
	}
	addr, _ = door(t, "u", "p", 4)
	w.SetEndpoint(Endpoint{Addr: addr, User: "u", Pass: "p"})
	sess, err := w.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var down bytes.Buffer
	o, err := sess.Run(context.Background(), Target{Host: "example.com", Port: 443}, []byte("hello"), make(chan []byte), &down, nopMeter{})
	if o != OutcomeError || err == nil || down.Len() != 0 {
		t.Fatalf("refused CONNECT: %v %v, %d bytes down", o, err, down.Len())
	}
}
