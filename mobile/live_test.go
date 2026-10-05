//go:build live

package mobile

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// Run locally only: go test -tags live ./mobile/ (needs local/subscription.url).
func TestLiveStartProveStop(t *testing.T) {
	raw, err := os.ReadFile("../local/subscription.url")
	if err != nil {
		t.Skip("no local/subscription.url")
	}
	if v := ValidateCatalogue(strings.TrimSpace(string(raw))); !strings.Contains(v, `"ok":true`) {
		t.Fatalf("validate: %s", v)
	}
	if err := Start(strings.TrimSpace(string(raw)), 11090, "live-test"); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	if err := Start("x", 11091, ""); err == nil {
		t.Fatal("second Start must fail while running")
	}
	var p struct {
		OK                bool
		Bytes, Ms         int64
		FirstByteMs       int64 `json:"first_byte_ms"`
		Path, Rail, Error string
	}
	// Watch the live counter while the probe streams: it must move before the end.
	done := make(chan struct{})
	var mid int64
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(20 * time.Millisecond):
				var pr struct{ Bytes, Total int64 }
				_ = json.Unmarshal([]byte(ProofProgress()), &pr)
				if pr.Bytes > 0 && pr.Bytes < 262144 && mid == 0 {
					mid = pr.Bytes
				}
			}
		}
	}()
	err = json.Unmarshal([]byte(ProveDelivery("", 20000)), &p)
	close(done)
	if err != nil {
		t.Fatal(err)
	}
	if got := ProofProgress(); got != `{"bytes":262144,"total":262144}` {
		t.Fatalf("progress after the proof = %s", got)
	}
	t.Logf("live counter mid-flight: %d bytes", mid)
	t.Logf("proof: ok=%v bytes=%d ms=%d fb=%d rail=%s err=%s", p.OK, p.Bytes, p.Ms, p.FirstByteMs, p.Rail, p.Error)
	if !p.OK || p.Bytes != 262144 || p.Path == "" {
		t.Fatalf("delivery not proven: %+v", p)
	}
	if !strings.Contains(StatusJSON(), `"leader"`) || ReceiptsJSON() == "[]" {
		t.Fatal("status/receipts empty after a proven flow")
	}
	Stop()
	if Running() {
		t.Fatal("still running after Stop")
	}
}
