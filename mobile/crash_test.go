package mobile

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A core that dies of a panic leaves its message and stack in the crash file,
// which the app sends with the journal on the next start; a new run empties it.
func TestCrashFileKeepsThePanic(t *testing.T) {
	if p := os.Getenv("FARVATER_CRASH_FILE"); p != "" {
		if err := SetCrashFile(p); err != nil {
			os.Exit(3)
		}
		var m map[string]int
		m["x"] = 1 // a nil map write: a panic nothing recovers
		return
	}
	path := filepath.Join(t.TempDir(), "core-crash.txt")
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashFileKeepsThePanic$")
	cmd.Env = append(os.Environ(), "FARVATER_CRASH_FILE="+path)
	if err := cmd.Run(); err == nil {
		t.Fatal("the child did not die")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "panic: assignment to entry in nil map") || !strings.Contains(string(b), "goroutine ") {
		t.Fatalf("crash file:\n%s", b)
	}
	if err := SetCrashFile(path); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); len(b) != 0 {
		t.Fatalf("not emptied: %d bytes", len(b))
	}
	if err := SetCrashFile(""); err != nil {
		t.Fatal(err)
	}
}
