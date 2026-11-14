package kilvater_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/kilvater"
)

// With an allow list a v2 key id opens the tunnel only if it is listed; v1
// keys are untouched, and without a list every derived id is taken as before.
func TestVerifierAllowList(t *testing.T) {
	var master, flat kilvater.Key
	rand.Read(master[:])
	rand.Read(flat[:])
	in, out := kilvater.KeyIDFor(master, []byte("subscriber-in")), kilvater.KeyIDFor(master, []byte("subscriber-out"))
	now := time.Now()
	tag := func(id kilvater.KeyID) string {
		return kilvater.NewTagV2(id, kilvater.DeriveKey(master, id), "/connect", now)
	}

	open := kilvater.NewVerifierConfig(kilvater.VerifierConfig{Master: &master})
	if n, _, why := open.VerifyDetail(tag(out), "/connect", now); n < 0 {
		t.Fatalf("no list: refused as %q", why)
	}

	v := kilvater.NewVerifierConfig(kilvater.VerifierConfig{Keys: []kilvater.Key{flat}, Master: &master,
		Allowed: []kilvater.KeyID{in}, AllowList: true})
	if n, _, why := v.VerifyDetail(tag(in), "/connect", now); n < 0 {
		t.Fatalf("listed id refused as %q", why)
	}
	if n, id, why := v.VerifyDetail(tag(out), "/connect", now); n >= 0 || why != kilvater.FailUnknown || id.KeyID != out {
		t.Fatalf("unlisted id: n=%d why=%q", n, why)
	}
	if n, _, why := v.VerifyDetail(kilvater.NewTag(flat, "/connect", now), "/connect", now); n < 0 {
		t.Fatalf("v1 key refused under an allow list: %q", why)
	}

	// An empty list is a list: nobody on v2.
	none := kilvater.NewVerifierConfig(kilvater.VerifierConfig{Master: &master, AllowList: true})
	if n, _, why := none.VerifyDetail(tag(in), "/connect", now); n >= 0 || why != kilvater.FailUnknown {
		t.Fatalf("empty list: n=%d why=%q", n, why)
	}

	// A reload takes a subscriber off.
	v.Reload(kilvater.VerifierConfig{Master: &master, AllowList: true})
	if n, _, _ := v.VerifyDetail(tag(in), "/connect", now); n >= 0 {
		t.Fatal("still accepted after the reload dropped it")
	}
}
