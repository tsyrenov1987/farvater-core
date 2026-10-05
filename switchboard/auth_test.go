package switchboard

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/catalogue"
)

// TestSocksAuth: with credentials set, the port is no open proxy. A client
// offering no authentication (what a port scanner on the device sends) is
// turned away, a wrong password is refused, and the right credentials reach
// the request stage (here an unroutable target, so nothing is dialed).
func TestSocksAuth(t *testing.T) {
	cat, err := catalogue.Parse([]byte("vless://00000000-0000-0000-0000-000000000000@127.0.0.1:9?security=tls&sni=example.com&type=tcp#dead"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.User, cfg.Pass = "session-user", "session-pass"
	s, err := New(cfg, cat)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.serveListener(ctx, ln) }()

	// talk writes each message and reads the expected number of reply bytes.
	talk := func(t *testing.T, msgs [][]byte, replies []int) [][]byte {
		t.Helper()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		var got [][]byte
		for i, m := range msgs {
			if _, err := c.Write(m); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, replies[i])
			if _, err := io.ReadFull(c, b); err != nil {
				t.Fatalf("message %d: %v", i, err)
			}
			got = append(got, b)
		}
		// The server must have closed after a refusal; after success it waits.
		return got
	}
	creds := func(u, p string) []byte {
		b := append([]byte{1, byte(len(u))}, u...)
		return append(append(b, byte(len(p))), p...)
	}

	t.Run("no auth offered", func(t *testing.T) {
		got := talk(t, [][]byte{{5, 1, 0}}, []int{2})
		if !bytes.Equal(got[0], []byte{5, 0xff}) {
			t.Fatalf("greeting reply %v, want [5 255]", got[0])
		}
	})
	t.Run("wrong password", func(t *testing.T) {
		got := talk(t, [][]byte{{5, 1, 2}, creds("session-user", "guess")}, []int{2, 2})
		if !bytes.Equal(got[0], []byte{5, 2}) || got[1][1] == 0 {
			t.Fatalf("replies %v, want [5 2] then a non-zero status", got)
		}
	})
	t.Run("right credentials", func(t *testing.T) {
		got := talk(t, [][]byte{
			{5, 2, 0, 2}, // offers both; must still be asked for the password
			creds("session-user", "session-pass"),
			{5, 1, 0, 1, 198, 18, 0, 2, 0x03, 0x55}, // 198.18.0.2:853
		}, []int{2, 2, 10})
		if !bytes.Equal(got[0], []byte{5, 2}) || !bytes.Equal(got[1], []byte{1, 0}) {
			t.Fatalf("auth replies %v %v, want [5 2] [1 0]", got[0], got[1])
		}
		if got[2][1] != 2 {
			t.Fatalf("request reply status %d, want 2 (reached the routing check)", got[2][1])
		}
	})
}
