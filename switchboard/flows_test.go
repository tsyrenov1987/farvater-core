package switchboard

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/catalogue"
)

// TestFlowsCountOnlyAdmittedRequests: the apps show Status().Flows as
// "connections this session". A port scanner's greeting, the iOS tunnel's
// liveness probe (a greeting and nothing more), a wrong password and a refused
// unroutable target are no app's connection, so none of them may count; an
// admitted request does.
func TestFlowsCountOnlyAdmittedRequests(t *testing.T) {
	cat, err := catalogue.Parse([]byte("vless://00000000-0000-0000-0000-000000000000@127.0.0.1:9?security=tls&sni=example.com&type=tcp#dead"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.User, cfg.Pass = "u", "p"
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

	// exchange writes each message, reads the reply sizes given, then hangs up.
	exchange := func(msgs [][]byte, replies []int) []byte {
		t.Helper()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		var last []byte
		for i, m := range msgs {
			if _, err := c.Write(m); err != nil {
				t.Fatal(err)
			}
			last = make([]byte, replies[i])
			if _, err := io.ReadFull(c, last); err != nil {
				t.Fatalf("message %d: %v", i, err)
			}
		}
		return last
	}
	auth := []byte{1, 1, 'u', 1, 'p'}

	exchange([][]byte{{5, 1, 0}}, []int{2})                                                  // scanner
	exchange([][]byte{{5, 1, 2}}, []int{2})                                                  // liveness probe
	exchange([][]byte{{5, 1, 2}, {1, 1, 'u', 1, 'x'}}, []int{2, 2})                          // wrong password
	exchange([][]byte{{5, 1, 2}, auth, {5, 1, 0, 1, 198, 18, 0, 2, 0, 53}}, []int{2, 2, 10}) // unroutable
	if n := s.Status().Flows; n != 0 {
		t.Fatalf("flows = %d after no admitted request, want 0", n)
	}
	rep := exchange([][]byte{{5, 1, 2}, auth, {5, 1, 0, 3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 1, 187}}, []int{2, 2, 10})
	if rep[1] != 0 {
		t.Fatalf("request reply status %d, want 0", rep[1])
	}
	if n := s.Status().Flows; n != 1 {
		t.Fatalf("flows = %d after one admitted request, want 1", n)
	}
}
