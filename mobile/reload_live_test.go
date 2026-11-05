//go:build live

package mobile

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Run locally only: go test -tags live -run TestLiveReload ./mobile/ (needs local/subscription.url).
// A download runs through the core over the live fleet; halfway through, the
// catalogue loses one path and Reload swaps the switchboard. The download must
// finish whole, new requests must go through the new switchboard, and the old
// one must close once the download is done.
func TestLiveReload(t *testing.T) {
	drainTick = 200 * time.Millisecond
	defer func() { drainTick = 5 * time.Second }()
	raw, err := os.ReadFile("../local/subscription.url")
	if err != nil {
		t.Skip("no local/subscription.url")
	}
	var f struct {
		OK          bool
		Text, Error string
		Paths       int
	}
	_ = json.Unmarshal([]byte(FetchCatalogue(strings.TrimSpace(string(raw)))), &f)
	if !f.OK {
		t.Fatalf("fetch: %s", f.Error)
	}
	lines := uriLines(f.Text)
	if len(lines) < 3 {
		t.Skipf("catalogue is not a list of links (%d lines)", len(lines))
	}
	t.Logf("catalogue: %d links, %d runnable", len(lines), f.Paths)
	if err := Start(f.Text, 11092, "live-test"); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	var p struct {
		OK          bool
		Path, Error string
	}
	_ = json.Unmarshal([]byte(ProveDelivery("", 20000)), &p)
	if !p.OK {
		t.Fatalf("proof before reload: %s", p.Error)
	}
	t.Logf("proof before reload via %s", p.Path)

	const size = 24 << 20
	mu.Lock()
	addr, u, pw := listen, user, pass
	mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c, err := socksConnect(ctx, addr, u, pw, "speed.cloudflare.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tc := tls.Client(c, &tls.Config{ServerName: "speed.cloudflare.com"})
	fmt.Fprintf(tc, "GET /__down?bytes=%d HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: farvater-live-test\r\nConnection: close\r\n\r\n", size)
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("download start: %v %v", resp, err)
	}
	got := make(chan int64, 1)
	errs := make(chan error, 1)
	go func() {
		var n int64
		buf := make([]byte, 64<<10)
		for {
			k, err := resp.Body.Read(buf)
			n += int64(k)
			if err == io.EOF {
				got <- n
				return
			}
			if err != nil {
				errs <- fmt.Errorf("after %d bytes: %w", n, err)
				return
			}
			time.Sleep(30 * time.Millisecond) // ~2 MB/s at most: the download outlives the reload
		}
	}()
	time.Sleep(3 * time.Second)
	mu.Lock()
	oldLife := life
	mu.Unlock()
	before := status(t)
	r := Reload(strings.Join(lines[:len(lines)-1], "\n"))
	t.Logf("reload: %s", r)
	if !strings.Contains(r, `"changed":true`) {
		t.Fatalf("reload = %s", r)
	}
	after := status(t)
	if len(after.Paths) >= len(before.Paths) || after.Flows < before.Flows || SocksUser() != u {
		t.Fatalf("after reload: paths %d -> %d, flows %d -> %d", len(before.Paths), len(after.Paths), before.Flows, after.Flows)
	}
	_ = json.Unmarshal([]byte(ProveDelivery("", 20000)), &p)
	if !p.OK {
		t.Fatalf("proof after reload: %s", p.Error)
	}
	t.Logf("proof after reload via %s", p.Path)
	select {
	case n := <-got:
		if n != size {
			t.Fatalf("download got %d of %d bytes", n, size)
		}
		t.Logf("download through the reload: %d bytes whole", n)
	case err := <-errs:
		t.Fatalf("download broke: %v", err)
	case <-ctx.Done():
		t.Fatal("download timed out")
	}
	c.Close()
	select {
	case <-oldLife.Done():
		t.Log("old switchboard closed after the download")
	case <-time.After(5 * time.Second):
		t.Fatal("old switchboard still open after its flows ended")
	}
}

// uriLines is the catalogue's share links, the subscription decoded from
// base64 if it is.
func uriLines(text string) []string {
	s := strings.TrimSpace(text)
	if !strings.Contains(s, "://") {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, err := enc.DecodeString(s); err == nil {
				s = string(b)
				break
			}
		}
	}
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); strings.Contains(l, "://") {
			out = append(out, l)
		}
	}
	return out
}
