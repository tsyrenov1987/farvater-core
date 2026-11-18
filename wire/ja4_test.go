package wire

import (
	"testing"

	"github.com/tsyrenov1987/farvater-core/ja4"
)

func ja4Of(t *testing.T, fp string) string {
	t.Helper()
	u := buildUConn(t, fp)
	a, _, err := ja4.Of(u.HandshakeState.Hello.Raw)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// chromeJA4 is what a real Chrome 157.0.8103.78 on macOS sent to
// tools/ja4cap on 2026-11-14: eighteen handshakes, one value. JA4 sorts
// ciphers and extensions, so Chrome's shuffling does not move it.
const chromeJA4 = "t13d1517h2_8daaf6152771_cb7bf5808d99"

// The chrome profile must hash to what the browser itself sends. When this
// fails after a profile update, capture a current Chrome with tools/ja4cap and
// compare field by field before touching the constant.
func TestChromeProfileHasTheJA4OfARealChrome(t *testing.T) {
	for i := 0; i < 5; i++ {
		if got := ja4Of(t, "chrome"); got != chromeJA4 {
			t.Fatalf("chrome JA4 = %s, a real Chrome 157 sends %s", got, chromeJA4)
		}
	}
}

// edge and firefox are pinned to what this core sends today, not to a capture:
// neither browser was at hand on 2026-11-14 (their fields were checked against
// the browsers on 2026-11-13, tlsfp_test.go). The test is a tripwire for an
// unintended change, not a proof of likeness.
func TestOtherProfilesKeepTheirJA4(t *testing.T) {
	for fp, want := range map[string]string{
		"edge":    "t13d1516h2_8daaf6152771_806a8c22fdea",
		"firefox": "t13d1517h2_8daaf6152771_3cbfd9057e0d",
	} {
		if got := ja4Of(t, fp); got != want {
			t.Errorf("%s JA4 = %s, was %s", fp, got, want)
		}
	}
}

func TestKilvaterTakesItsProfileFromFpc(t *testing.T) {
	const base = "kilvater://00@192.0.2.1:8080?sni=a.example&path=%2Fconnect&fp=chrome"
	for q, want := range map[string]string{
		"":             "chrome",
		"&fpc=edge":    "edge",
		"&fpc=Edge":    "edge",
		"&fpc=chrome":  "chrome",
		"&fpc=firefox": "chrome", // no HTTP/2 profile to go with it yet
		"&fpc=opera":   "chrome", // a name from a newer catalogue
	} {
		s, err := ParseURI(base + q + "#x")
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		if s.Fingerprint != want {
			t.Errorf("%q: fingerprint %q, want %q", q, s.Fingerprint, want)
		}
	}
}
