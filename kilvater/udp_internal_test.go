package kilvater

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// A key holder must not reach the server's own loopback or LAN over UDP either,
// unless AllowPrivate is on: the check is the same one TCP gets, since udp dials
// through s.dialer() like tcp does.
func TestUDPRefusesPrivateTargetByDefault(t *testing.T) {
	_, port, _ := net.SplitHostPort(mustUDPEcho(t).LocalAddr().String())
	for _, target := range []string{"127.0.0.1:" + port, "localhost:" + port} {
		var down bytes.Buffer
		upR, upW := io.Pipe()
		upW.Close()
		(&Server{}).udp(context.Background(), target, upR, &down)

		typ, body, err := ReadFrame(&down, nil)
		if err != nil || typ != FrameClose || len(body) != 1 || body[0] != 1 {
			t.Fatalf("%s: want CLOSE(1), got type=%d body=%v err=%v", target, typ, body, err)
		}
	}
}

// Each datagram crosses the tunnel as its own frame: two datagrams of unlike
// sizes come back whole, neither split nor joined. A byte-stream shaper here
// would break this.
func TestUDPEchoPreservesBoundaries(t *testing.T) {
	echo := mustUDPEcho(t)
	go func() {
		b := make([]byte, 64<<10)
		for {
			n, from, err := echo.ReadFromUDP(b)
			if err != nil {
				return
			}
			echo.WriteToUDP(b[:n], from)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	upR, upW := io.Pipe()
	downR, downW := io.Pipe()
	done := make(chan struct{})
	go func() {
		(&Server{AllowPrivate: true}).udp(ctx, echo.LocalAddr().String(), upR, downW)
		close(done)
	}()

	// Drive one datagram at a time so UDP cannot reorder the two answers.
	for i, msg := range [][]byte{[]byte("one"), bytes.Repeat([]byte("x"), 1500)} {
		if err := WriteFrame(upW, FrameDgram, msg); err != nil {
			t.Fatalf("datagram %d: write: %v", i, err)
		}
		typ, body, err := ReadFrame(downR, nil)
		if err != nil {
			t.Fatalf("datagram %d: read: %v", i, err)
		}
		if typ != FrameDgram {
			t.Fatalf("datagram %d: frame type %d, want FrameDgram (%d)", i, typ, FrameDgram)
		}
		if !bytes.Equal(body, msg) {
			t.Fatalf("datagram %d: boundary broken: got %d bytes, want %d", i, len(body), len(msg))
		}
	}

	cancel()
	upW.Close()
	downR.Close() // unblock the final CLOSE frame the test is no longer reading
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("udp did not return after the association ended")
	}
}

func mustUDPEcho(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
