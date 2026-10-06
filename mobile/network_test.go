package mobile

import (
	"encoding/json"
	"testing"
)

// The apps name networks their own way; the core files them under its keys,
// so the memory of a network is found whichever app reported it.
func TestNetworkNames(t *testing.T) {
	for in, want := range map[string]string{"cellular": "cell", " Mobile ": "cell", "cell": "cell", "ethernet": "wired",
		"wifi": "wifi", "wifi:0A1B2C3D": "wifi:0a1b2c3d", "": ""} {
		if got := contextName(in); got != want {
			t.Errorf("contextName(%q) = %q, want %q", in, got, want)
		}
	}
	const dead = "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:9?security=tls&sni=example.com&type=tcp#dead"
	if err := Start(dead, freePort(t), "cellular"); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	ctx := func() string {
		var st struct {
			Ctx string `json:"ctx"`
		}
		_ = json.Unmarshal([]byte(StatusJSON()), &st)
		return st.Ctx
	}
	if c := ctx(); c != "cell" {
		t.Fatalf("Start(..., \"cellular\") files under %q, want cell", c)
	}
	SetNetwork("wifi:0a1b2c3d")
	if c := ctx(); c != "wifi:0a1b2c3d" {
		t.Fatalf("after SetNetwork: %q", c)
	}
}
