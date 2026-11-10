package mobile

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestReloadKeepsPortAndFlows: a catalogue fetched while the tunnel runs
// replaces the running one with no restart. The same paths change nothing;
// new paths get a new switchboard on the same port with the same credentials
// and the session's counters; a connection open on the old switchboard is
// served to its end, and then the old one closes.
func TestReloadKeepsPortAndFlows(t *testing.T) {
	drainTick = 20 * time.Millisecond
	defer func() { drainTick = 5 * time.Second }()
	const a = "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:9?security=tls&sni=example.com&type=tcp#a"
	const b = "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:10?security=tls&sni=example.com&type=tcp#b"

	if got := Reload(a); !strings.Contains(got, `"ok":false`) {
		t.Fatalf("reload while stopped = %s", got)
	}
	port := freePort(t)
	if err := Start(a+"\n"+b, port, "wifi:test"); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	u, p := SocksUser(), SocksPass()

	if got := Reload(b + "\n" + a); got != `{"changed":false,"ok":true,"paths":2}` {
		t.Fatalf("same paths, other order: %s", got)
	}
	if got := Reload("http://example.com/sub"); !strings.Contains(got, `"ok":false`) {
		t.Fatalf("reload by address = %s", got)
	}

	// A connection the old switchboard holds, authenticated, its request not sent yet.
	held, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	_ = held.SetDeadline(time.Now().Add(8 * time.Second))
	auth := append([]byte{1, byte(len(u))}, u...)
	auth = append(append(auth, byte(len(p))), p...)
	_, _ = held.Write([]byte{5, 1, 2})
	reply := make([]byte, 2)
	if _, err := io.ReadFull(held, reply); err != nil || reply[1] != 2 {
		t.Fatalf("greeting: %v %v", reply, err)
	}
	_, _ = held.Write(auth)
	if _, err := io.ReadFull(held, reply); err != nil || reply[1] != 0 {
		t.Fatalf("auth: %v %v", reply, err)
	}
	waitActive(t, 1)
	before := status(t)
	mu.Lock()
	oldLife := life
	mu.Unlock()

	const moved = "vless://00000000-0000-0000-0000-000000000000@127.0.0.2:9?security=tls&sni=example.com&type=tcp#a"
	got := Reload(moved + "\n" + b)
	if got != `{"changed":true,"ok":true,"paths":2}` {
		t.Fatalf("moved node: %s", got)
	}
	if SocksUser() != u || SocksPass() != p || !Running() {
		t.Fatal("reload changed the credentials or stopped the core")
	}
	after := status(t)
	if after.Ctx != "wifi:test" || after.Flows != before.Flows || after.Uptime < before.Uptime {
		t.Fatalf("counters not carried: before %+v after %+v", before, after)
	}
	var servers []string
	for _, ps := range after.Paths {
		servers = append(servers, ps.Server)
	}
	if strings.Join(servers, ",") != "127.0.0.2:9,127.0.0.1:10" {
		t.Fatalf("paths after reload: %v", servers)
	}

	// New connections reach the new switchboard with the same credentials.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := socksConnect(ctx, addr, u, p, "198.18.0.2:853"); err == nil || !strings.Contains(err.Error(), "status 2") {
		t.Fatalf("after reload: err = %v, want connect status 2", err)
	}
	// The held one is still served by the old switchboard: an unroutable
	// target gets its refusal, not a reset.
	_, _ = held.Write([]byte{5, 1, 0, 1, 198, 18, 0, 2, 3, 85})
	rep := make([]byte, 10)
	if _, err := io.ReadFull(held, rep); err != nil || rep[1] != 2 {
		t.Fatalf("held connection after reload: %v %v", rep, err)
	}
	held.Close()
	select {
	case <-oldLife.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the old switchboard did not close once its flows were done")
	}
	if _, err := socksConnect(ctx, addr, u, p, "198.18.0.2:853"); err == nil || !strings.Contains(err.Error(), "status 2") {
		t.Fatalf("after the old one closed: err = %v, want connect status 2", err)
	}

	// Stop frees the port as before.
	Stop()
	deadline := time.Now().Add(2 * time.Second)
	for {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			ln.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("port still taken after Stop: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type statusView struct {
	Ctx    string `json:"ctx"`
	Flows  int64  `json:"flows"`
	Uptime int64  `json:"uptime_sec"`
	Paths  []struct {
		Server string `json:"server"`
	} `json:"paths"`
}

func status(t *testing.T) statusView {
	t.Helper()
	var v statusView
	if err := json.Unmarshal([]byte(StatusJSON()), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func waitActive(t *testing.T, n int64) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if s := current(); s != nil && s.Active() == n {
			return
		}
	}
	t.Fatalf("active never reached %d", n)
}

// TestReloadOnRestrictedNetwork: a catalogue fetched while the network is
// restricted (allow-listed sites only) is taken, not refused; the new
// switchboard starts in the restricted variant of the same network. Refused,
// the apps retried every five minutes all evening (Farvater Android 0.1.0 (40)).
func TestReloadOnRestrictedNetwork(t *testing.T) {
	const a = "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:9?security=tls&sni=example.com&type=tcp#a"
	const b = "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:10?security=tls&sni=example.com&type=tcp#b"
	if err := Start(a, freePort(t), "cell"); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	mu.Lock()
	sb.EnterRestricted()
	mu.Unlock()
	if got := Reload(a + "\n" + b); got != `{"changed":true,"ok":true,"paths":2}` {
		t.Fatalf("reload on a restricted network: %s", got)
	}
	if s := status(t); s.Ctx != "cell:wl" {
		t.Fatalf("ctx after the reload %q, want cell:wl", s.Ctx)
	}
}
