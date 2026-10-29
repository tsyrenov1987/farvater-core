package mobile

import (
	"encoding/json"
	"math"
	"runtime/debug"
	"testing"
	"time"
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

// TestMemoryValve: past its line the valve opens (and says so in MemoryJSON);
// turned off it stays shut.
func TestMemoryValve(t *testing.T) {
	defer SetMemoryValve(0)
	SetMemoryValve(1)
	deadline := time.Now().Add(3 * time.Second)
	for valveFired.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	var m struct{ Valve uint64 }
	if err := json.Unmarshal([]byte(MemoryJSON()), &m); err != nil || m.Valve == 0 {
		t.Fatalf("valve never opened: %+v %v", m, err)
	}
	SetMemoryValve(0)
	time.Sleep(1200 * time.Millisecond)
	n := valveFired.Load()
	time.Sleep(1500 * time.Millisecond)
	if valveFired.Load() != n {
		t.Fatal("valve opened while off")
	}
}
