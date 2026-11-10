package switchboard

import (
	"testing"

	"github.com/tsyrenov1987/farvater-core/catalogue"
)

// The app shows where the traffic comes out: Status carries the catalogue's
// "#exit=" country on each path row, and nothing for a path without one.
func TestStatusCarriesExitCountry(t *testing.T) {
	cat, err := catalogue.Parse([]byte("#exit=SE\n" +
		"vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?security=tls&sni=a.example.com&type=tcp#a\n" +
		"vless://00000000-0000-0000-0000-000000000000@127.0.0.1:2?security=tls&sni=b.example.com&type=tcp#b"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(DefaultConfig(), cat)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range s.Status().Paths {
		got[p.ID] = p.Exit
	}
	if got["a"] != "SE" || got["b"] != "" || len(got) != 2 {
		t.Fatalf("exits %v: want a=SE, b none", got)
	}
}
