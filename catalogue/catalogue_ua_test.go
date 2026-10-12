package catalogue

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
)

// The subscription fetch must name the OS: the provider tells the iPhone app from
// the Android one only by this header (same core on both).
func TestFetchUserAgentNamesOS(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		w.Write([]byte("vless://x@1.2.3.4:443#a"))
	}))
	defer srv.Close()
	if _, err := Fetch(srv.URL); err != nil {
		t.Fatal(err)
	}
	if want := "farvater-core/0.1 (" + runtime.GOOS + ")"; got != want {
		t.Fatalf("User-Agent %q, want %q", got, want)
	}
}
