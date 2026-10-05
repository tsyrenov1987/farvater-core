package mobile

import (
	"encoding/json"
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

// TestMemoryJSON: the report parses and its parts fit inside the total.
func TestMemoryJSON(t *testing.T) {
	var m struct{ Total, Heap, Stacks, Goroutines uint64 }
	if err := json.Unmarshal([]byte(MemoryJSON()), &m); err != nil {
		t.Fatal(err)
	}
	if m.Heap == 0 || m.Stacks == 0 || m.Goroutines == 0 || m.Total < m.Heap+m.Stacks {
		t.Fatalf("implausible report %+v", m)
	}
}
