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

// With the device set, the fetch carries the HWID headers a device-limited
// Remnawave panel needs; without it, none of them.
func TestFetchSendsDeviceHeaders(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Write([]byte("vless://x@1.2.3.4:443#a"))
	}))
	defer srv.Close()
	Fetch(srv.URL)
	if got.Get("x-hwid") != "" {
		t.Fatalf("x-hwid without a device: %q", got.Get("x-hwid"))
	}
	Device.HWID, Device.OS, Device.OSVersion, Device.Model = "d1f0", "Android", "14", "Xiaomi 23078PND5G"
	defer func() { Device.HWID, Device.OS, Device.OSVersion, Device.Model = "", "", "", "" }()
	Fetch(srv.URL)
	if got.Get("x-hwid") != "d1f0" || got.Get("x-device-os") != "Android" || got.Get("x-ver-os") != "14" || got.Get("x-device-model") != "Xiaomi 23078PND5G" {
		t.Fatalf("headers %v", got)
	}
}
