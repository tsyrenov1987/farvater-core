package switchboard

import (
	"sync/atomic"
	"testing"
	"time"
)

// A catalogue's names are resolved once each and all at once: with the
// resolver down the start waits one timeout, not one per line.
func TestNamesAreResolvedOnceEachAndTogether(t *testing.T) {
	var calls atomic.Int32
	old := lookupIP
	lookupIP = func(h string) string {
		calls.Add(1)
		time.Sleep(200 * time.Millisecond)
		return "10.0.0." + h[1:2]
	}
	defer func() { lookupIP = old }()
	var hosts []string
	for i := 0; i < 60; i++ {
		hosts = append(hosts, []string{"n1.example.com", "n2.example.com", "n3.example.com", "192.0.2.7"}[i%4])
	}
	start := time.Now()
	ips := resolveIPs(hosts)
	if d := time.Since(start); d > time.Second {
		t.Fatalf("60 lines over 3 names took %v", d)
	}
	if calls.Load() != 3 {
		t.Fatalf("%d lookups for 3 names", calls.Load())
	}
	if ips["n2.example.com"] != "10.0.0.2" || ips["192.0.2.7"] != "192.0.2.7" {
		t.Fatalf("resolved %v", ips)
	}
}
