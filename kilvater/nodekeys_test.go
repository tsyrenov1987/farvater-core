package kilvater_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/kilvater"
)

// NodeMaster must be exactly HMAC-SHA256(master, "kilvater/node\0" || node),
// so the worker (JavaScript) reproduces it byte for byte.
func TestNodeMasterMatchesSpec(t *testing.T) {
	var master kilvater.Key
	for i := range master {
		master[i] = byte(0x40 + i)
	}
	got := kilvater.NodeMaster(master, "advin")
	m := hmac.New(sha256.New, master[:])
	m.Write([]byte("kilvater/node\x00advin"))
	if !bytes.Equal(got[:], m.Sum(nil)) {
		t.Fatal("NodeMaster does not match the documented HMAC")
	}
	if kilvater.NodeMaster(master, "de3") == got {
		t.Fatal("two nodes got the same node master")
	}
	// Frozen vector shared with the worker's own test (orden-worker): master
	// 0x40..0x5f, node "advin", subscriber "subscriber-42".
	id := kilvater.KeyIDFor(master, []byte("subscriber-42"))
	k := kilvater.DeriveKey(got, id)
	if g := hex.EncodeToString(got[:]); g != "3031ad6ff4434584ba181dfb21018237a536183be4bb461ac1a610b55aa8110e" {
		t.Errorf("node master vector changed: %s", g)
	}
	if id.String() != "660e46ebcda448ec" {
		t.Errorf("kid vector changed: %s", id)
	}
	if g := hex.EncodeToString(k[:]); g != "07f7c4062a2221116f88e8a9b18b19d2a490647e346242d53a602dfee02d5a0f" {
		t.Errorf("node-bound key vector changed: %s", g)
	}
}

func TestVerifierNodeBoundKeys(t *testing.T) {
	fleet := testMaster(t)
	nodeA := kilvater.NodeMaster(fleet, "a")
	nodeB := kilvater.NodeMaster(fleet, "b")
	id := kilvater.KeyIDFor(fleet, []byte("sub"))
	now := time.Now()

	keyA := kilvater.DeriveKey(nodeA, id)
	keyB := kilvater.DeriveKey(nodeB, id)
	keyFleet := kilvater.DeriveKey(fleet, id)

	// Node a during the move: its own master plus the fleet master.
	moving := kilvater.NewVerifierConfig(kilvater.VerifierConfig{Master: &nodeA, Masters: []kilvater.Key{fleet}})
	for name, k := range map[string]kilvater.Key{"node a": keyA, "fleet": keyFleet} {
		if n, got, why := moving.VerifyDetail(kilvater.NewTagV2(id, k, "/connect", now), "/connect", now); n < 0 || got.KeyID != id || why != "" {
			t.Errorf("%s key refused while moving: n=%d why=%q", name, n, why)
		}
	}
	if h := moving.MasterHits(); len(h) != 2 || h[0] != 1 || h[1] != 1 {
		t.Errorf("master hits %v, want [1 1]", h)
	}
	if n, _, why := moving.VerifyDetail(kilvater.NewTagV2(id, keyB, "/connect", now), "/connect", now); n >= 0 || why != kilvater.FailMAC {
		t.Errorf("node b key on node a: n=%d why=%q, want refused as mac", n, why)
	}

	// Node a after the move: its own master only — the fleet key no longer opens it.
	bound := kilvater.NewVerifierConfig(kilvater.VerifierConfig{Master: &nodeA})
	if n, got, why := bound.VerifyDetail(kilvater.NewTagV2(id, keyFleet, "/connect", now), "/connect", now); n >= 0 || why != kilvater.FailMAC || got.KeyID != id {
		t.Errorf("fleet key on bound node: n=%d why=%q id=%s", n, why, got.KeyID)
	}
	if n, _, _ := bound.VerifyDetail(kilvater.NewTagV2(id, keyA, "/connect", now), "/connect", now); n < 0 {
		t.Error("node a key refused on node a")
	}

	// Revoked and replayed tags report their reason.
	rev := kilvater.NewVerifierConfig(kilvater.VerifierConfig{Master: &nodeA, Revoked: []kilvater.KeyID{id}})
	if _, _, why := rev.VerifyDetail(kilvater.NewTagV2(id, keyA, "/connect", now), "/connect", now); why != kilvater.FailRevoked {
		t.Errorf("revoked: why=%q", why)
	}
	tag := kilvater.NewTagV2(id, keyA, "/connect", now)
	bound.VerifyDetail(tag, "/connect", now)
	if _, _, why := bound.VerifyDetail(tag, "/connect", now); why != kilvater.FailReplay {
		t.Errorf("replay: why=%q", why)
	}
	old := now.Add(-time.Hour)
	if _, _, why := bound.VerifyDetail(kilvater.NewTagV2(id, keyA, "/connect", old), "/connect", now); why != kilvater.FailWindow {
		t.Errorf("stale: why=%q", why)
	}
	none := kilvater.NewVerifierConfig(kilvater.VerifierConfig{Keys: []kilvater.Key{keyA}})
	if _, _, why := none.VerifyDetail(kilvater.NewTagV2(id, keyA, "/connect", now), "/connect", now); why != kilvater.FailNoV2 {
		t.Errorf("no master: why=%q", why)
	}
}
