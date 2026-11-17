package kilvater

import (
	"crypto/rand"
	"testing"
	"time"
)

// KL-08 (2): a v3 tag is good only for the name it was made for — one of the
// node's Authorities or the request's Host — and v2 tags keep working.
func TestTagV3BoundToAuthority(t *testing.T) {
	var fleet Key
	rand.Read(fleet[:])
	node := NodeMaster(fleet, "de3")
	id := KeyIDFor(fleet, []byte("sub"))
	k := DeriveKey(node, id)
	now := time.Unix(1_800_000_000, 0)
	const path = "/connect"

	cases := []struct {
		name, made, host string
		names          []string
		want           string // "" accept, else the Fail* reason
	}{
		{"configured name, Host rewritten by nginx", "Files.Example.app:8080", "127.0.0.1:8081", []string{"files.example.app"}, ""},
		{"Host passed through", "files.example.app:8080", "FILES.example.app.", nil, ""},
		{"one of several names", "k1.cdn.example", "127.0.0.1:8081", []string{"files.example.app", "k1.cdn.example"}, ""},
		{"made for another site", "other.example", "127.0.0.1:8081", []string{"files.example.app"}, FailMAC},
		{"no names, Host is the upstream", "files.example.app", "127.0.0.1:8081", nil, FailMAC},
		{"no names, no Host", "files.example.app", "", nil, FailMAC},
	}
	for _, c := range cases {
		v := NewVerifierConfig(VerifierConfig{Master: &fleet, Masters: []Key{node}, Authorities: c.names})
		n, ident, why := v.VerifyDetailHost(NewTagV3(id, k, c.made, path, now), c.host, path, now)
		if why != c.want || (c.want == "") != (n >= 0) {
			t.Errorf("%s: n=%d why=%q, want %q", c.name, n, why, c.want)
		}
		if c.want == "" && (!ident.V2 || ident.KeyID != id) {
			t.Errorf("%s: identity %+v", c.name, ident)
		}
	}

	v := NewVerifierConfig(VerifierConfig{Master: &fleet, Masters: []Key{node}, Authorities: []string{"files.example.app"}})
	// A v2 tag is accepted as before, whatever the names.
	if n, _, why := v.VerifyDetailHost(NewTagV2(id, k, path, now), "127.0.0.1:8081", path, now); n < 0 {
		t.Fatalf("v2 refused: %s", why)
	}
	// The path is still covered.
	if n, _, _ := v.VerifyDetailHost(NewTagV3(id, k, "files.example.app", "/other", now), "", path, now); n >= 0 {
		t.Fatal("v3 made for another path accepted")
	}
	// A v3 tag is single use.
	tag := NewTagV3(id, k, "files.example.app", path, now)
	if n, _, _ := v.VerifyDetailHost(tag, "", path, now); n < 0 {
		t.Fatal("v3 refused")
	}
	if _, _, why := v.VerifyDetailHost(tag, "", path, now); why != FailReplay {
		t.Fatalf("replayed v3: why=%q", why)
	}
	// Outside the window, revoked and unlisted ids are refused as for v2.
	if _, _, why := v.VerifyDetailHost(NewTagV3(id, k, "files.example.app", path, now.Add(-3*TagWindow)), "", path, now); why != FailWindow {
		t.Fatalf("old v3: why=%q", why)
	}
	vr := NewVerifierConfig(VerifierConfig{Master: &fleet, Masters: []Key{node}, Authorities: []string{"files.example.app"}, Revoked: []KeyID{id}})
	if _, _, why := vr.VerifyDetailHost(NewTagV3(id, k, "files.example.app", path, now), "", path, now); why != FailRevoked {
		t.Fatalf("revoked v3: why=%q", why)
	}
	va := NewVerifierConfig(VerifierConfig{Master: &fleet, Masters: []Key{node}, Authorities: []string{"files.example.app"}, AllowList: true})
	if _, _, why := va.VerifyDetailHost(NewTagV3(id, k, "files.example.app", path, now), "", path, now); why != FailUnknown {
		t.Fatalf("unlisted v3: why=%q", why)
	}
	// The node master counts the accept.
	if h := v.MasterHits(); len(h) != 2 || h[1] != 2 {
		t.Fatalf("master hits %v", h)
	}
}
