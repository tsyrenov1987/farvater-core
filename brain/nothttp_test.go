package brain

import (
	"slices"
	"testing"
)

// A path that looks like no HTTP (Hysteria 2 under Salamander) leads and takes
// flows on proven delivery, but never stands in for a failing one: even in a
// storm, delivering best, it is never a flow's second or third dial, so whoever
// blocks the path a flow went to never sees it light up next.
func TestNotHTTPNeverStandsIn(t *testing.T) {
	paths := []PathInfo{
		{ID: "A", SNI: "a", IP: "1", Rail: "reality"},
		{ID: "B", SNI: "b", IP: "2", Rail: "xhttp"},
		{ID: "C", SNI: "c", IP: "3", Rail: "ws"},
		{ID: "H", SNI: "h", IP: "4", Rail: "hy2", NotHTTP: true},
		{ID: "K", SNI: "k", IP: "5", Rail: "grpc"},
	}
	b := New(DefaultConfig(), "t", paths, 1)
	now := int64(1000)
	b.Pick(now, "h", DstTLS443)
	for range 8 {
		now += 100
		b.Observe(deliv("H", now))
	}
	b.Observe(reset("B", now))
	b.Observe(reset("C", now))
	led, explored := 0, 0
	for range 300 {
		now += 100
		d := b.Pick(now, "h", DstTLS443)
		if !b.Breaker.Storm(now) {
			t.Fatal("two tripped rails should hold a storm")
		}
		if d.Secondary == "H" || d.Tertiary == "H" {
			t.Fatalf("H stood in for %s: %+v", d.Primary, d)
		}
		if d.Primary == "H" {
			led++
			continue
		}
		explored++
		if d.Secondary == "" || d.Tertiary != "" {
			t.Fatalf("from %s the one stand-in is the other HTTP-like path: %+v", d.Primary, d)
		}
	}
	if b.Leader() != "H" || led == 0 || explored == 0 {
		t.Fatalf("leader %q, flows on H %d, on the others %d: H should lead and the others be explored", b.Leader(), led, explored)
	}
}

// Behind the UDP leader a path that looks like no HTTP comes after every
// available HTTP-like one, whatever its delivery, and before the tripped ones.
func TestUDPOrderPutsNotHTTPAfterTheRest(t *testing.T) {
	paths := []PathInfo{{ID: "A", SNI: "a", IP: "1", Rail: "reality"}, {ID: "B", SNI: "b", IP: "2", Rail: "xhttp"}, {ID: "H", SNI: "h", IP: "3", Rail: "hy2", NotHTTP: true}, {ID: "D", SNI: "d", IP: "4", Rail: "ws"}}
	b := New(DefaultConfig(), "t", paths, 1)
	b.Pick(1000, "h", DstTLS443)
	for i := range 3 { // H delivers best, on too few receipts to take the lead
		b.Observe(deliv("H", 2000+int64(i)))
	}
	b.Observe(reset("D", 2100))
	b.Pick(3000, "h", DstTLS443)
	if b.Leader() != "A" {
		t.Fatalf("leader %q, want A", b.Leader())
	}
	if got, want := b.UDPOrder(3000), []string{"A", "B", "H", "D"}; !slices.Equal(got, want) {
		t.Fatalf("UDP order %v, want %v", got, want)
	}
}
