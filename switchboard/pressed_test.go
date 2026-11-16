package switchboard

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/tsyrenov1987/farvater-core/catalogue"
)

// Under memory pressure a new flow is refused at once, with no dial and no
// receipt, and counted; once the pressure is off flows are served again.
func TestPressedRefusesNewFlows(t *testing.T) {
	cat, err := catalogue.Parse([]byte("vless://00000000-0000-0000-0000-000000000000@127.0.0.1:9?security=tls&sni=example.com&type=tcp#dead"))
	if err != nil {
		t.Fatal(err)
	}
	var on atomic.Bool
	on.Store(true)
	cfg := DefaultConfig()
	cfg.Direct = []string{"localhost"}
	cfg.Pressed = on.Load
	s, err := New(cfg, cat)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.serveListener(ctx, ln) }()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := target.Addr().(*net.TCPAddr).Port

	c, rep := socksTo(t, ln.Addr().String(), "localhost", port)
	c.Close()
	if rep != 1 {
		t.Fatalf("pressed: reply %d, want 1 (general failure)", rep)
	}
	st := s.Status()
	if st.Shed != 1 || st.Flows != 0 || len(s.Receipts()) != 0 {
		t.Fatalf("pressed: shed %d flows %d receipts %d, want 1/0/0", st.Shed, st.Flows, len(s.Receipts()))
	}
	on.Store(false)
	c, rep = socksTo(t, ln.Addr().String(), "localhost", port)
	c.Close()
	if rep != 0 {
		t.Fatalf("pressure off: reply %d, want 0", rep)
	}
	if s.Status().Shed != 1 {
		t.Fatalf("pressure off: shed %d, want still 1", s.Status().Shed)
	}
}
