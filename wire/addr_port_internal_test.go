package wire

import "testing"

func TestAppendAddrRejectsPortOutOfRange(t *testing.T) {
	for _, port := range []int{-1, 65536, 70000} {
		tg := Target{Host: "example.org", Port: port}
		if _, err := appendPortAddr(nil, tg); err == nil {
			t.Errorf("appendPortAddr port %d: no error", port)
		}
		if _, err := appendSocksAddr(nil, tg); err == nil {
			t.Errorf("appendSocksAddr port %d: no error", port)
		}
	}
	if _, err := appendPortAddr(nil, Target{Host: "example.org", Port: 443}); err != nil {
		t.Fatal(err)
	}
}
