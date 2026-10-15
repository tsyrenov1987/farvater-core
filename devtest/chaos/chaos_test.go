//go:build chaos

package chaos

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

// go test -tags chaos ./devtest/chaos/ [-run 'TestChaos/name'] runs the
// scenarios on this machine; the phone runs the same through gomobile.
func TestChaos(t *testing.T) {
	if p, err := strconv.Atoi(os.Getenv("CHAOS_PORT")); err == nil {
		socksPort = p
	}
	names := strings.Split(Scenarios(), ",")
	if only := os.Getenv("CHAOS"); only != "" {
		names = strings.Split(only, ",")
	}
	for _, n := range names {
		t.Run(n, func(t *testing.T) {
			out := Run(n)
			var r Result
			if err := json.Unmarshal([]byte(out), &r); err != nil {
				t.Fatal(err)
			}
			b, _ := json.MarshalIndent(r, "", "  ")
			t.Log(string(b))
			if !r.Pass {
				t.Fail()
			}
		})
	}
}
