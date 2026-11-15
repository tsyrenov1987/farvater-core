package mobile

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// TestFetchCatalogueTriesTheTunnelFirst: while the core runs, the catalogue
// is asked for through its SOCKS door first (F-125); when the tunnel does not
// bring it (here its only path is dead), directly. Stopped, it goes directly.
func TestFetchCatalogueTriesTheTunnelFirst(t *testing.T) {
	tunnelFetchTimeout = 3 * time.Second
	defer func() { tunnelFetchTimeout = 12 * time.Second }()
	const link = "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:9?security=tls&sni=example.com&type=tcp#a"
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, link)
	}))
	defer srv.Close()
	type result struct {
		OK    bool   `json:"ok"`
		Paths int    `json:"paths"`
		Error string `json:"error"`
	}
	// By name: the switchboard refuses a loopback address before any path.
	u := "http://localhost:" + strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port) + "/s"
	fetch := func() (r result) {
		if err := json.Unmarshal([]byte(FetchCatalogue(u)), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}

	if r := fetch(); !r.OK || r.Paths != 1 {
		t.Fatalf("stopped: %+v", r)
	}

	if err := Start(link, freePort(t), "wifi:test"); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	before := status(t).Flows
	start := time.Now()
	if r := fetch(); !r.OK || r.Paths != 1 {
		t.Fatalf("running, dead tunnel: %+v", r)
	}
	if el := time.Since(start); el > tunnelFetchTimeout+5*time.Second {
		t.Fatalf("fetch took %v", el)
	}
	if after := status(t).Flows; after <= before {
		t.Fatalf("the tunnel was not asked first: flows %d -> %d", before, after)
	}
	if hits.Load() != 2 {
		t.Fatalf("server saw %d requests, want 2 (stopped + the direct one after the dead tunnel)", hits.Load())
	}
}
