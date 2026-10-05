//go:build live

package mobile

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Apps keep HTTP/2 connections open between requests and close them when
// they please. That idle time is not throttling: a page, a bulk download, an
// idle pause, more requests on the same connections and a close by the app
// must leave receipts without stalls or failures, and no rail tripped.
func TestLiveKeepAliveIsNotAStall(t *testing.T) {
	raw, err := os.ReadFile("../local/subscription.url")
	if err != nil {
		t.Skip("no local/subscription.url")
	}
	if err := Start(strings.TrimSpace(string(raw)), 11092, "live-idle"); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, hostport string) (net.Conn, error) {
			return socksConnect(ctx, "127.0.0.1:11092", hostport)
		},
		ForceAttemptHTTP2: true,
		IdleConnTimeout:   5 * time.Minute,
	}
	cl := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	get := func(u string) {
		resp, err := cl.Get(u)
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		t.Logf("%s: %s %s, %d bytes", u, resp.Proto, resp.Status, n)
	}
	page := "https://www.wikipedia.org/"
	bulk := "https://speed.cloudflare.com/__down?bytes="
	get(page)
	get(bulk + "1048576")
	time.Sleep(15 * time.Second) // idle on open connections, well past the stall window
	get(page)
	get(bulk + "65536")
	time.Sleep(6 * time.Second)
	tr.CloseIdleConnections() // the app closes its pool
	time.Sleep(2 * time.Second)

	var st struct {
		Paths []struct {
			ID, Rail, Tripped string
		}
		Recent []struct {
			Path, End, Dst string
			Down           int64
			Stalls         int
			FirstByteMs    int64 `json:"first_byte_ms"`
		} `json:"recent_receipts"`
	}
	if err := json.Unmarshal([]byte(StatusJSON()), &st); err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, r := range st.Recent {
		if r.Dst != "www.wikipedia.org" && r.Dst != "speed.cloudflare.com" {
			continue
		}
		seen++
		t.Logf("receipt %s %s down=%d fb=%d stalls=%d", r.Dst, r.End, r.Down, r.FirstByteMs, r.Stalls)
		if r.FirstByteMs >= 0 && (r.Stalls > 0 || r.End == "stall_abandon" || r.End == "timeout") {
			t.Errorf("idle keep-alive scored as a failure: %+v", r)
		}
	}
	if seen == 0 {
		t.Fatal("no receipts for the test flows")
	}
	for _, p := range st.Paths {
		if p.Tripped != "" {
			t.Errorf("rail %s (%s) tripped: %s", p.ID, p.Rail, p.Tripped)
		}
	}
}
