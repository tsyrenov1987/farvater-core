package brain

import (
	"slices"
	"testing"
)

// UDP follows the leader even past a challenger whose posterior is a little
// better (hysteresis keeps the leader), then the rest by mean; a tripped path
// is tried last, never left out.
func TestUDPOrder(t *testing.T) {
	paths := []PathInfo{{ID: "A", SNI: "a", IP: "1", Rail: "reality"}, {ID: "B", SNI: "b", IP: "2", Rail: "xhttp"}, {ID: "C", SNI: "c", IP: "3", Rail: "ws"}, {ID: "D", SNI: "d", IP: "4", Rail: "hy2"}}
	b := New(DefaultConfig(), "t", paths, 1)
	b.Pick(1000, "h", DstTLS443)
	feed := func(path, pattern string) { // o = delivered, s = stalled; never two stalls in a row
		for i, c := range pattern {
			r := ok(100 * KB)
			if c == 's' {
				r = stalled(18 * KB)
			}
			r.Path, r.AtMs = path, 2000+int64(i)
			b.Observe(r)
		}
	}
	feed("A", "ososososoo") // mean ≈ 0.54
	feed("C", "osososoooo") // mean ≈ 0.61: better, but not by enough to lead
	b.Observe(reset("D", 2100))
	b.Pick(3000, "h", DstTLS443)
	if b.Leader() != "A" {
		t.Fatalf("leader %q, want A", b.Leader())
	}
	if got, want := b.UDPOrder(3000), []string{"A", "C", "B", "D"}; !slices.Equal(got, want) {
		t.Fatalf("UDP order %v, want %v", got, want)
	}
}
