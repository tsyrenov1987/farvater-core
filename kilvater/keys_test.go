package kilvater_test

import (
	"bytes"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/kilvater"
)

func testMaster(t *testing.T) kilvater.Key {
	t.Helper()
	var m kilvater.Key
	rand.Read(m[:])
	return m
}

// DeriveKey must be deterministic, vary with the id, and match the documented
// HKDF scheme byte for byte (a worker in another language must be able to
// reproduce it).
func TestDeriveKeyMatchesSpec(t *testing.T) {
	master := testMaster(t)
	id := kilvater.KeyIDFor(master, []byte("subscriber-42"))

	k1 := kilvater.DeriveKey(master, id)
	if k1 != kilvater.DeriveKey(master, id) {
		t.Fatal("DeriveKey is not deterministic")
	}
	other := kilvater.KeyIDFor(master, []byte("subscriber-43"))
	if other == id {
		t.Fatal("two subscribers got the same key id")
	}
	if kilvater.DeriveKey(master, other) == k1 {
		t.Fatal("two ids derived the same key")
	}

	// Independent recomputation of the spec: HKDF-SHA256(master, "", "kilvater/key\0"||id, 32).
	want, err := hkdf.Key(sha256.New, master[:], nil, "kilvater/key\x00"+string(id[:]), 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1[:], want) {
		t.Fatalf("DeriveKey does not match the documented HKDF scheme")
	}
}

// A v2 tag is accepted by its key id with a master and no flat key list at
// all: the server derives the key, it does not scan. This is the O(1) path.
func TestVerifyV2ByKeyIDNoFlatKeys(t *testing.T) {
	master := testMaster(t)
	id := kilvater.KeyIDFor(master, []byte("alice"))
	k := kilvater.DeriveKey(master, id)
	v := kilvater.NewVerifierConfig(kilvater.VerifierConfig{Master: &master}) // no Keys

	tag := kilvater.NewTagV2(id, k, "/connect", time.Now())
	if v.Verify(tag, "/connect", time.Now()) < 0 {
		t.Fatal("a valid v2 tag was rejected")
	}
}

// The derive path does not depend on the flat key list: a v2 tag verifies even
// when the list is large and does not contain the derived key.
func TestVerifyV2IgnoresFlatKeyList(t *testing.T) {
	master := testMaster(t)
	var decoys []kilvater.Key
	for i := 0; i < 1000; i++ {
		decoys = append(decoys, testMaster(t))
	}
	v := kilvater.NewVerifierConfig(kilvater.VerifierConfig{Keys: decoys, Master: &master})

	id := kilvater.KeyIDFor(master, []byte("bob"))
	tag := kilvater.NewTagV2(id, kilvater.DeriveKey(master, id), "/connect", time.Now())
	if v.Verify(tag, "/connect", time.Now()) < 0 {
		t.Fatal("v2 tag rejected; it should derive, not scan the flat list")
	}
}

// A v1 tag is still accepted while a master is configured: deployed clients
// keep working through the migration.
func TestVerifyV1StillAcceptedAlongsideMaster(t *testing.T) {
	master := testMaster(t)
	var flat kilvater.Key
	rand.Read(flat[:])
	v := kilvater.NewVerifierConfig(kilvater.VerifierConfig{Keys: []kilvater.Key{flat}, Master: &master})

	tag := kilvater.NewTag(flat, "/connect", time.Now())
	if v.Verify(tag, "/connect", time.Now()) < 0 {
		t.Fatal("a v1 tag was rejected while a master was set")
	}
}

func TestVerifyV2NoMasterRejected(t *testing.T) {
	master := testMaster(t)
	id := kilvater.KeyIDFor(master, []byte("carol"))
	tag := kilvater.NewTagV2(id, kilvater.DeriveKey(master, id), "/connect", time.Now())

	v := kilvater.NewVerifier(nil) // v1-only verifier, no master
	if v.Verify(tag, "/connect", time.Now()) >= 0 {
		t.Fatal("a v2 tag was accepted without a master")
	}
}

func TestVerifyV2WrongPathAndReplay(t *testing.T) {
	master := testMaster(t)
	id := kilvater.KeyIDFor(master, []byte("dave"))
	k := kilvater.DeriveKey(master, id)
	v := kilvater.NewVerifierConfig(kilvater.VerifierConfig{Master: &master})

	tag := kilvater.NewTagV2(id, k, "/connect", time.Now())
	if v.Verify(tag, "/other", time.Now()) >= 0 {
		t.Fatal("a v2 tag for /connect was accepted on /other")
	}
	if v.Verify(tag, "/connect", time.Now()) < 0 {
		t.Fatal("first use on the right path should pass")
	}
	if v.Verify(tag, "/connect", time.Now()) >= 0 {
		t.Fatal("a replayed v2 tag should be rejected")
	}
}

// Revoking one key id rejects only that id; the others keep working.
func TestRevokeByKeyID(t *testing.T) {
	master := testMaster(t)
	a := kilvater.KeyIDFor(master, []byte("revoke-me"))
	b := kilvater.KeyIDFor(master, []byte("keep-me"))
	v := kilvater.NewVerifierConfig(kilvater.VerifierConfig{Master: &master, Revoked: []kilvater.KeyID{a}})

	ta := kilvater.NewTagV2(a, kilvater.DeriveKey(master, a), "/connect", time.Now())
	if v.Verify(ta, "/connect", time.Now()) >= 0 {
		t.Fatal("a revoked key id was accepted")
	}
	tb := kilvater.NewTagV2(b, kilvater.DeriveKey(master, b), "/connect", time.Now())
	if v.Verify(tb, "/connect", time.Now()) < 0 {
		t.Fatal("revoking one id rejected another")
	}
}

// A reload (what SIGHUP triggers) revokes one id and leaves the rest; it swaps
// the key material under concurrent verification without a restart.
func TestReloadRevokesPinpoint(t *testing.T) {
	master := testMaster(t)
	a := kilvater.KeyIDFor(master, []byte("user-a"))
	b := kilvater.KeyIDFor(master, []byte("user-b"))
	v := kilvater.NewVerifierConfig(kilvater.VerifierConfig{Master: &master})

	// Before the reload both pass (fresh tags each time to dodge replay).
	if v.Verify(kilvater.NewTagV2(a, kilvater.DeriveKey(master, a), "/connect", time.Now()), "/connect", time.Now()) < 0 {
		t.Fatal("user-a rejected before revocation")
	}

	v.Reload(kilvater.VerifierConfig{Master: &master, Revoked: []kilvater.KeyID{a}})

	if v.Verify(kilvater.NewTagV2(a, kilvater.DeriveKey(master, a), "/connect", time.Now()), "/connect", time.Now()) >= 0 {
		t.Fatal("user-a still accepted after revocation")
	}
	if v.Verify(kilvater.NewTagV2(b, kilvater.DeriveKey(master, b), "/connect", time.Now()), "/connect", time.Now()) < 0 {
		t.Fatal("user-b rejected after revoking only user-a")
	}
}

func TestParseKeyID(t *testing.T) {
	var id kilvater.KeyID
	rand.Read(id[:])
	got, err := kilvater.ParseKeyID(id.String())
	if err != nil || got != id {
		t.Fatalf("round trip: got %v err %v, want %v", got, err, id)
	}
	if _, err := kilvater.ParseKeyID(hex.EncodeToString([]byte{1, 2, 3})); err == nil {
		t.Fatal("a short key id should not parse")
	}
}
