package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadPrefixFile(t *testing.T) {
	dir := t.TempDir()
	if l, err := readPrefixFile(filepath.Join(dir, "none")); err != nil || len(l) != 0 {
		t.Fatalf("missing file: %v %v", l, err)
	}
	p := filepath.Join(dir, "deny")
	os.WriteFile(p, []byte("# relays\n192.0.2.9\n198.51.100.0/24 # net\n\n"), 0o600)
	l, err := readPrefixFile(p)
	if err != nil || len(l) != 2 || l[0].String() != "192.0.2.9/32" || l[1].String() != "198.51.100.0/24" {
		t.Fatalf("got %v %v", l, err)
	}
	os.WriteFile(p, []byte("192.0.2.9\nnot-an-address\n"), 0o600)
	if _, err := readPrefixFile(p); err == nil {
		t.Fatal("a bad line must fail the read")
	}
}
