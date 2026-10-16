package switchboard

import (
	"context"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/catalogue"
)

// A dial given up while it waits for its handshake slot (a race already won by
// another path, a flow the app closed) leaves the slot to the next dial: dials
// given up in a storm must not push every later flow on the path seconds back.
func TestADialGivenUpLeavesItsHandshakeSlot(t *testing.T) {
	cat, err := catalogue.Parse([]byte("vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?security=tls&sni=a.example.com&type=tcp#a"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(DefaultConfig(), cat)
	if err != nil {
		t.Fatal(err)
	}
	p := s.Paths()[0]
	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = s.pace(ctx, p)
	}
	start := time.Now()
	if err := s.pace(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if w := time.Since(start); w > 1500*time.Millisecond {
		t.Fatalf("a live dial waited %v behind ten dials given up, want under 1.5 s", w.Round(time.Millisecond))
	}
}
