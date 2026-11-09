//go:build windows && windowslive

package service

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/catalogue"
	"github.com/tsyrenov1987/farvater-core/desktop"
	"github.com/tsyrenov1987/farvater-core/switchboard"
)

const deadPath = "vless://00000000-0000-0000-0000-000000000000@192.0.2.1:9?security=tls&sni=example.com&type=tcp#dead"

func ps(t *testing.T, cmd string) string {
	t.Helper()
	out, _ := exec.Command("powershell", "-NoProfile", "-Command", cmd).CombinedOutput()
	return strings.TrimSpace(string(out))
}

func tunnelRoutes(t *testing.T) string {
	return ps(t, "Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Where-Object { $_.DestinationPrefix -in '0.0.0.0/1','128.0.0.0/1' } | ForEach-Object { $_.DestinationPrefix }")
}

func dnsRule(t *testing.T) bool {
	out, _ := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=Farvater DNS").CombinedOutput()
	return strings.Contains(string(out), "Farvater DNS")
}

func waitLive(t *testing.T, s *Session, what string, ok func(State) bool) State {
	t.Helper()
	for end := time.Now().Add(60 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if st := s.CurrentState(); ok(st) {
			return st
		}
	}
	t.Fatalf("timed out waiting for %s: %+v", what, s.CurrentState())
	return State{}
}

// TestLiveSession brings the real tunnel up and down through the service's
// session, several times in one process as the service does. The catalogue and
// the delivery proof are the only stand-ins: CI has no access code.
func TestLiveSession(t *testing.T) {
	h := RealHooks()
	h.Fetch = func(string) ([]byte, *catalogue.Provider, error) { return []byte(deadPath), nil, nil }
	h.Prove = func(context.Context, *switchboard.Switchboard, string, string, string) Proof {
		return Proof{OK: true, Bytes: 262144, Path: "dead", Rail: "tls"}
	}
	s := New(t.TempDir(), h, t.Logf)
	defer s.Close(false)
	defer func() { _ = desktop.Off() }()
	s.prefs.Source = "https://joinorden.com/hsub/ORDEN-AAAAA-BBBBB"

	if got := tunnelRoutes(t); got != "" {
		t.Fatalf("routes before the first connect: %s", got)
	}
	for i := 1; i <= 3; i++ {
		s.Connect()
		st := waitLive(t, s, "on", func(st State) bool { return st.State == "on" || st.State == "failed" })
		if st.State != "on" {
			t.Fatalf("cycle %d: %+v", i, st)
		}
		routes := tunnelRoutes(t)
		t.Logf("cycle %d up: routes %q, rule %v", i, routes, dnsRule(t))
		if !strings.Contains(routes, "0.0.0.0/1") || !strings.Contains(routes, "128.0.0.0/1") || !dnsRule(t) {
			t.Fatalf("cycle %d: the machine is not routed", i)
		}
		s.Disconnect()
		waitLive(t, s, "off", func(st State) bool { return st.State == "off" })
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) && (tunnelRoutes(t) != "" || dnsRule(t)) {
			time.Sleep(100 * time.Millisecond)
		}
		if got := tunnelRoutes(t); got != "" || dnsRule(t) {
			t.Fatalf("cycle %d: left behind: routes %q, rule %v", i, got, dnsRule(t))
		}
	}
}
