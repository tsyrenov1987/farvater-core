package mobile

import (
	"encoding/json"
	"testing"
)

// The apps run olcRTC calls themselves: they say so before Start, poll which
// calls the core wants up, and hand over or take back each one's door.
func TestHostedPathsThroughTheBindings(t *testing.T) {
	const olc = "olcrtc://wbstream?vp8channel@room-1#d823fa01cb3e0609b67322f7cf984c4ee2e4ce2e294936fc24ef38c9e59f4799$o"
	const dead = "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:9?security=tls&sni=example.com&type=tcp#dead"
	SetHostedKinds("")
	if err := Start(olc, freePort(t), "cell"); err == nil {
		Stop()
		t.Fatal("an app that runs no olcRTC started on an olcRTC path alone")
	}
	SetHostedKinds(" OLCRTC , ")
	defer SetHostedKinds("")
	if err := Start(dead+"\n"+olc, freePort(t), "cell"); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	hosted := func() []map[string]any {
		t.Helper()
		var h []map[string]any
		if err := json.Unmarshal([]byte(HostedJSON()), &h); err != nil || len(h) != 1 {
			t.Fatalf("HostedJSON %s: %v", HostedJSON(), err)
		}
		return h
	}
	if h := hosted()[0]; h["id"] != "o" || h["room"] != "room-1" || h["key"] == "" || h["want"] != false || h["up"] != false {
		t.Fatalf("%v", h)
	}
	SetHostedEndpoint("o", 40001, "u", "p")
	if h := hosted()[0]; h["up"] != true {
		t.Fatalf("door handed over: %v", h)
	}
	SetHostedEndpoint("o", 0, "", "")
	if h := hosted()[0]; h["up"] != false {
		t.Fatalf("door taken back: %v", h)
	}
	Stop()
	if HostedJSON() != "[]" {
		t.Fatalf("not running: %s", HostedJSON())
	}
}
