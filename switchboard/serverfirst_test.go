package switchboard

import (
	"io"
	"net"
	"testing"
	"time"
)

// greeted connects to example.com:port through the board and says nothing:
// how long until the server's first byte reaches the app.
func greeted(t *testing.T, addr string, port byte) time.Duration {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	req := append([]byte{5, 1, 0, 5, 1, 0, 3, 11}, "example.com"...)
	if _, err := c.Write(append(req, 0, port)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 2+10)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	return time.Since(start)
}

// A mail client waits for the server's greeting: the board does not hold the
// dial FirstPayloadWait for a first payload that is not coming.
func TestAServerFirstProtocolIsDialledAtOnce(t *testing.T) {
	s, addr, _ := udpBoard(t)
	for _, id := range []string{"a", "b", "c"} {
		s.wires[id] = &streamWire{id: id, n: 100}
	}
	imap, other := greeted(t, addr, 143), greeted(t, addr, 81)
	t.Logf("greeting after %v on port 143, %v on port 81", imap.Round(time.Millisecond), other.Round(time.Millisecond))
	if imap > 200*time.Millisecond {
		t.Fatalf("the greeting on port 143 took %v", imap)
	}
	if other < s.cfg.FirstPayloadWait {
		t.Fatalf("port 81 was dialled after %v, before FirstPayloadWait", other)
	}
}
