package mobile

import (
	"slices"
	"testing"
)

// The apps show names in their own script; SetDirect matches by the ASCII form.
func TestDirectNamesShowAndComeBack(t *testing.T) {
	shown := DirectNames("https://Сбербанк.рф/login, *.tbank.ru 1.2.3.4 nonsense")
	if want := `["сбербанк.рф","tbank.ru","1.2.3.4"]`; shown != want {
		t.Fatalf("DirectNames = %s, want %s", shown, want)
	}
	SetDirect("сбербанк.рф\ntbank.ru\n1.2.3.4")
	defer SetDirect("")
	mu.Lock()
	got := slices.Clone(direct)
	mu.Unlock()
	if want := []string{"xn--80abap1arsf.xn--p1ai", "tbank.ru", "1.2.3.4"}; !slices.Equal(got, want) {
		t.Fatalf("SetDirect kept %q, want %q", got, want)
	}
	if DirectNames("") != "[]" {
		t.Fatalf("DirectNames(\"\") = %s, want []", DirectNames(""))
	}
}

// A probe that went around the paths would prove a delivery no path made.
func TestDirectNeverCoversTheProbe(t *testing.T) {
	got := withoutProbes(
		[]string{"cloudflare.com", "tbank.ru", "speed.cloudflare.com", "probe.example", "example"},
		[]string{DefaultProbeURL, "https://Probe.Example/x"},
	)
	if want := []string{"tbank.ru"}; !slices.Equal(got, want) {
		t.Fatalf("withoutProbes = %q, want %q", got, want)
	}
}
