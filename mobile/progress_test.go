package mobile

import (
	"io"
	"strings"
	"testing"
)

// The live counter must see the probe body as it streams, not only at the end.
func TestProofProgressCountsTheBody(t *testing.T) {
	probeRead.Store(0)
	probeSize.Store(262144)
	r := io.LimitReader(strings.NewReader(strings.Repeat("x", 300000)), 100000)
	if _, err := io.Copy(countingDiscard{}, r); err != nil {
		t.Fatal(err)
	}
	if got := ProofProgress(); got != `{"bytes":100000,"total":262144}` {
		t.Fatalf("progress = %s", got)
	}
}
