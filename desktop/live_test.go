//go:build desktoplive

package desktop

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"

	"github.com/tsyrenov1987/farvater-core/catalogue"
	"github.com/tsyrenov1987/farvater-core/switchboard"
)

// FV_CATALOGUE=<file or URL> go test -tags desktoplive ./desktop -run Live -v
// An app on the "machine" (a second stack) resolves through the tunnel's DNS
// and fetches over HTTPS; the real switchboard carries it.
func TestLiveThroughEngine(t *testing.T) {
	src := os.Getenv("FV_CATALOGUE")
	var cat *catalogue.Catalogue
	var err error
	if strings.HasPrefix(src, "https://") {
		cat, err = catalogue.Load(src)
	} else {
		b, _ := os.ReadFile(src)
		cat, err = catalogue.Parse(b)
	}
	if err != nil {
		t.Fatal(err)
	}
	cfg := switchboard.DefaultConfig()
	cfg.User, cfg.Pass = rand.Text(), rand.Text()
	cfg.RuDirect = true
	cfg.ProbeURL = "https://www.gstatic.com/generate_204"
	sb, err := switchboard.New(cfg, cat)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	sb.Attach(ctx)
	o := newOS(t, ctx)
	if _, err := Start(ctx, o, sb.ServeConn, cfg.User, cfg.Pass, t.Logf); err != nil {
		t.Fatal(err)
	}
	resolve := func(name string) netip.Addr {
		dc, err := gonet.DialUDP(o.st, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(dnsAddr.AsSlice()), Port: 53}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		defer dc.Close()
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
		b.StartQuestions()
		b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
		q, _ := b.Finish()
		dc.SetDeadline(time.Now().Add(5 * time.Second))
		dc.Write(q)
		buf := make([]byte, 512)
		n, err := dc.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		var p dnsmessage.Parser
		p.Start(buf[:n])
		p.SkipAllQuestions()
		p.AnswerHeader()
		a, _ := p.AResource()
		return netip.AddrFrom4(a.A)
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			h, _, _ := net.SplitHostPort(addr)
			ip := resolve(h)
			return gonet.DialContextTCP(ctx, o.st, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ip.AsSlice()), Port: 443}, ipv4.ProtocolNumber)
		},
		TLSClientConfig: &tls.Config{},
	}}
	get := func(u string) string {
		for i := 0; i < 3; i++ {
			resp, err := client.Get(u)
			if err != nil {
				t.Logf("%s: %v", u, err)
				time.Sleep(2 * time.Second)
				continue
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return string(b)
		}
		t.Fatalf("%s failed", u)
		return ""
	}
	trace := get("https://www.cloudflare.com/cdn-cgi/trace")
	for _, l := range strings.Split(trace, "\n") {
		if strings.HasPrefix(l, "ip=") || strings.HasPrefix(l, "loc=") {
			t.Log("abroad:", l)
		}
	}
	t.Log("ru-direct (ifconfig.me):", strings.TrimSpace(get("https://ifconfig.me/ip")))
}
