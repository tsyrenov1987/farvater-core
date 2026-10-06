package wire

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

type nopMeter struct{}

func (nopMeter) Up([]byte)   {}
func (nopMeter) Down([]byte) {}

// echoTCP returns what it reads and closes once the client has finished.
func echoTCP(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// flowEcho carries one flow over the path to a TCP echo: the prelude and a
// later chunk must come back. finish then ends the flow from the app's side
// and reports how it ended and how long that took.
func flowEcho(t *testing.T, uri string) (finish func() (Outcome, time.Duration)) {
	t.Helper()
	spec, err := ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	w, err := Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	return flowEchoOver(t, w)
}

// flowEchoOver is flowEcho over a wire already built.
func flowEchoOver(t *testing.T, w Wire) (finish func() (Outcome, time.Duration)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	sess, err := w.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port := echoTCP(t)
	up := make(chan []byte, 1)
	pr, pw := io.Pipe()
	ended := make(chan Outcome, 1)
	go func() {
		o, _ := sess.Run(ctx, Target{Host: "127.0.0.1", Port: port}, []byte("hello "), up, pw, nopMeter{})
		pw.Close()
		ended <- o
	}()
	for i, want := range []string{"hello ", "world"} {
		if i > 0 {
			up <- []byte(want)
		}
		got := make([]byte, len(want))
		if _, err := io.ReadFull(pr, got); err != nil || string(got) != want {
			t.Fatalf("echo %q (%v), want %q", got, err, want)
		}
	}
	return func() (Outcome, time.Duration) {
		start := time.Now()
		close(up)
		go func() { _, _ = io.Copy(io.Discard, pr) }()
		select {
		case o := <-ended:
			return o, time.Since(start)
		case <-time.After(5 * time.Second):
			t.Fatal("the flow did not end")
			return 0, 0
		}
	}
}

func TestTrojanFlow(t *testing.T) {
	flowEcho(t, fmt.Sprintf("trojan://pw@127.0.0.1:%d?sni=farvater.test&allowInsecure=1#t", xrayTrojan(t)))
}

// VMess ends its body with an empty chunk: the server then finishes upstream,
// so the app's finish ends the flow at once, not on the idle timer.
func TestVMessFlow(t *testing.T) {
	finish := flowEcho(t, fmt.Sprintf("vmess://%s@127.0.0.1:%d?security=tls&sni=farvater.test&allowInsecure=1&type=tcp#t", testUUID, xrayVMess(t)))
	if o, d := finish(); o != OutcomeClientFin || d > time.Second {
		t.Fatalf("the flow ended %v after %v, want client_fin at once", o, d)
	}
}
