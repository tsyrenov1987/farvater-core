package main

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/kilvater"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadVerifierConfig(t *testing.T) {
	dir := t.TempDir()
	var master kilvater.Key
	rand.Read(master[:])
	masterPath := filepath.Join(dir, "master.txt")
	writeFile(t, masterPath, hex.EncodeToString(master[:])+"\n")

	var flat kilvater.Key
	rand.Read(flat[:])
	keysPath := filepath.Join(dir, "keys.txt")
	writeFile(t, keysPath, "# a key\n"+hex.EncodeToString(flat[:])+"\n")

	// Master and a missing keys file: fine, v2-only.
	cfg, err := loadVerifierConfig(filepath.Join(dir, "absent.txt"), masterPath, "")
	if err != nil {
		t.Fatalf("master-only config: %v", err)
	}
	if cfg.Master == nil || len(cfg.Keys) != 0 {
		t.Fatalf("master-only config: master=%v keys=%d", cfg.Master != nil, len(cfg.Keys))
	}

	// Keys and no master: fine, v1-only.
	cfg, err = loadVerifierConfig(keysPath, "", "")
	if err != nil {
		t.Fatalf("keys-only config: %v", err)
	}
	if cfg.Master != nil || len(cfg.Keys) != 1 {
		t.Fatalf("keys-only config: master=%v keys=%d", cfg.Master != nil, len(cfg.Keys))
	}

	// Neither: an error, nobody could authenticate.
	if _, err := loadVerifierConfig(filepath.Join(dir, "absent.txt"), "", ""); err == nil {
		t.Fatal("empty config should be an error")
	}

	// Revocation list parses.
	id := kilvater.KeyIDFor(master, []byte("gone"))
	revPath := filepath.Join(dir, "revoked.txt")
	writeFile(t, revPath, "# revoked\n"+id.String()+"\n")
	cfg, err = loadVerifierConfig(keysPath, masterPath, revPath)
	if err != nil {
		t.Fatalf("full config: %v", err)
	}
	if len(cfg.Revoked) != 1 || cfg.Revoked[0] != id {
		t.Fatalf("revoked not loaded: %v", cfg.Revoked)
	}
}

// SIGHUP re-reads the files and applies a revocation without a restart.
func TestInstallReloadOnSIGHUP(t *testing.T) {
	dir := t.TempDir()
	var master kilvater.Key
	rand.Read(master[:])
	masterPath := filepath.Join(dir, "master.txt")
	writeFile(t, masterPath, hex.EncodeToString(master[:]))
	revPath := filepath.Join(dir, "revoked.txt")
	writeFile(t, revPath, "")
	keysPath := filepath.Join(dir, "absent.txt")

	load := func() (kilvater.VerifierConfig, error) {
		return loadVerifierConfig(keysPath, masterPath, revPath)
	}
	cfg, err := load()
	if err != nil {
		t.Fatal(err)
	}
	v := kilvater.NewVerifierConfig(cfg)
	installReload(v, load)

	id := kilvater.KeyIDFor(master, []byte("user"))
	k := kilvater.DeriveKey(master, id)
	accepts := func() bool {
		return v.Verify(kilvater.NewTagV2(id, k, "/connect", time.Now()), "/connect", time.Now()) >= 0
	}
	if !accepts() {
		t.Fatal("key rejected before revocation")
	}

	writeFile(t, revPath, id.String()+"\n")
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for accepts() {
		if time.Now().After(deadline) {
			t.Fatal("SIGHUP did not apply the revocation")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
