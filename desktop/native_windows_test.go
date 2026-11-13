//go:build windows

package desktop

import (
	"strings"
	"testing"
	"time"
)

// The IP helper picks the same default route as Get-NetRoute did.
func TestNativeDefaultRouteMatchesPowerShell(t *testing.T) {
	idx, hop, err := nativeDefaultRoute()
	if err != nil {
		t.Fatal(err)
	}
	out, err := run("powershell", "-NoProfile", "-Command", defaultRouteCmd)
	if err != nil {
		t.Skipf("powershell: %v %s", err, out)
	}
	pidx, phop, err := parseDefaultRoute(out)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("native %d %q, powershell %d %q", idx, hop, pidx, phop)
	if idx != pidx || (phop != "" && hop != phop) {
		t.Fatalf("native %d %q != powershell %d %q", idx, hop, pidx, phop)
	}
}

func TestNativeAdapterDNS(t *testing.T) {
	idx, _, err := nativeDefaultRoute()
	if err != nil {
		t.Fatal(err)
	}
	up := adapterDNS(idx)
	t.Logf("interface %d dns %v, suffixes %v", idx, up, registrySuffixes())
	if len(up) == 0 {
		t.Fatal("no DNS servers on the default interface")
	}
}

func TestRunTimeoutWindows(t *testing.T) {
	old := runTimeout
	runTimeout = 500 * time.Millisecond
	defer func() { runTimeout = old }()
	start := time.Now()
	_, err := run("powershell", "-NoProfile", "-Command", "Start-Sleep -Seconds 20")
	if err == nil || !strings.Contains(err.Error(), "no answer") {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if d := time.Since(start); d > 8*time.Second {
		t.Fatalf("run took %s", d)
	}
}
