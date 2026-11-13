//go:build !windows

package desktop

import (
	"strings"
	"testing"
	"time"
)

// A tool that never answers must not hold Up: run gives up after runTimeout.
func TestRunTimeout(t *testing.T) {
	old := runTimeout
	runTimeout = 200 * time.Millisecond
	defer func() { runTimeout = old }()
	start := time.Now()
	_, err := run("sleep", "10")
	if err == nil || !strings.Contains(err.Error(), "no answer") {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("run took %s", d)
	}
}
