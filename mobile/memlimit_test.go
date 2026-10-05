package mobile

import (
	"math"
	"runtime/debug"
	"testing"
)

// TestSetMemoryLimit: the iOS tunnel's budget reaches the runtime, and zero
// leaves whatever limit is in force.
func TestSetMemoryLimit(t *testing.T) {
	defer debug.SetMemoryLimit(math.MaxInt64)
	SetMemoryLimit(32 << 20)
	if got := debug.SetMemoryLimit(-1); got != 32<<20 {
		t.Fatalf("limit = %d, want %d", got, 32<<20)
	}
	SetMemoryLimit(0)
	if got := debug.SetMemoryLimit(-1); got != 32<<20 {
		t.Fatalf("zero changed the limit to %d", got)
	}
}
