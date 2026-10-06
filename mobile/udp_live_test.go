//go:build live

package mobile

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// dnsQuery asks for the A record of example.com.
func dnsQuery(id uint16) []byte {
	q := []byte{byte(id >> 8), byte(id), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range []string{"example", "com"} {
		q = append(append(q, byte(len(l))), l...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

// Run locally only: go test -tags live -run UDP ./mobile/ (needs local/subscription.url).
// UDP the way hev-socks5-tunnel sends it: a DNS question to 1.1.1.1 by IP and
// to a resolver by name, each in its own association, must be answered
// through the paths.
func TestLiveUDP(t *testing.T) {
	raw, err := os.ReadFile("../local/subscription.url")
	if err != nil {
		t.Skip("no local/subscription.url")
	}
	if err := Start(strings.TrimSpace(string(raw)), 11092, "live-udp"); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	var p struct{ OK bool }
	if err := json.Unmarshal([]byte(ProveDelivery("", 20000)), &p); err != nil || !p.OK {
		t.Fatalf("no TCP delivery first: %v", err)
	}
	for i, to := range []struct {
		addr []byte // SOCKS5 address
		name string
	}{
		{[]byte{1, 1, 1, 1, 1, 0, 53}, "1.1.1.1"},
		{append(append([]byte{3, 15}, "one.one.one.one"...), 0, 53), "one.one.one.one"},
	} {
		c, err := net.Dial("tcp", "127.0.0.1:11092")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(15 * time.Second))
		u, pw := SocksUser(), SocksPass()
		hello := append([]byte{5, 1, 2, 1, byte(len(u))}, u...)
		hello = append(append(hello, byte(len(pw))), pw...)
		hello = append(hello, 5, 5, 0, 1, 0, 0, 0, 0, 0, 0)
		if _, err := c.Write(hello); err != nil {
			t.Fatal(err)
		}
		rep := make([]byte, 2+2+10)
		if _, err := io.ReadFull(c, rep); err != nil || rep[1] != 2 || rep[3] != 0 || rep[5] != 0 {
			t.Fatalf("handshake %v %v", rep, err)
		}
		id := uint16(0x4a00 + i)
		q := dnsQuery(id)
		frame := append([]byte{byte(len(q) >> 8), byte(len(q)), byte(3 + len(to.addr))}, to.addr...)
		start := time.Now()
		if _, err := c.Write(append(frame, q...)); err != nil {
			t.Fatal(err)
		}
		h := make([]byte, 3)
		if _, err := io.ReadFull(c, h); err != nil {
			t.Fatalf("%s: no answer: %v", to.name, err)
		}
		body := make([]byte, int(h[2])-3+int(binary.BigEndian.Uint16(h[:2])))
		if _, err := io.ReadFull(c, body); err != nil {
			t.Fatal(err)
		}
		a := body[int(h[2])-3:]
		if len(a) < 12 || binary.BigEndian.Uint16(a) != id || a[3]&0x0f != 0 || binary.BigEndian.Uint16(a[6:8]) == 0 {
			t.Fatalf("%s: not an answer to the question (%d bytes)", to.name, len(a))
		}
		t.Logf("%s: answered in %d ms, %d answer records, reply framed from atype %d", to.name, time.Since(start).Milliseconds(), binary.BigEndian.Uint16(a[6:8]), body[0])
	}
	var st struct{ UDP int64 }
	_ = json.Unmarshal([]byte(StatusJSON()), &st)
	if st.UDP < 2 {
		t.Fatalf("status udp = %d, want 2", st.UDP)
	}
}
