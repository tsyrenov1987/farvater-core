package wire

import (
	"testing"
	"time"
)

// TestChromeUACHIsChromes: the Sec-CH-UA string for a major version is the
// one that Chrome version sends, brand order included.
func TestChromeUACHIsChromes(t *testing.T) {
	for v, want := range map[int]string{
		120: `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
		124: `"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"`,
		131: `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`,
		133: `"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"`,
	} {
		if got := chromeUACHFor(v); got != want {
			t.Errorf("Chrome %d:\n got %s\nwant %s", v, got, want)
		}
	}
	if chromeUACH() != chromeUACH() {
		t.Error("Sec-CH-UA changes between requests")
	}
}

func TestChromeMajorFollowsTheCalendar(t *testing.T) {
	day := func(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 12, 0, 0, 0, time.UTC) }
	for _, c := range []struct {
		at   time.Time
		want int
	}{
		{day(2025, 1, 1), 157},   // a clock behind the anchor
		{day(2026, 11, 3), 157},  // Chrome 157 stable
		{day(2026, 11, 16), 157}, // 13 days on
		{day(2026, 11, 17), 158}, // two weeks on
		{day(2027, 1, 12), 162},
		{day(2035, 1, 1), 183}, // a clock far ahead is held to a year past the anchor
	} {
		if got := chromeMajorAt(c.at); got != c.want {
			t.Errorf("%s: Chrome %d, want %d", c.at.Format(time.DateOnly), got, c.want)
		}
	}
}
