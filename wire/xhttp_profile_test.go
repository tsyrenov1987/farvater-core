package wire

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	xserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/splithttp"
)

// xprofCase is one request profile: the node's xhttpSettings and the link
// parameters that make the core speak them.
type xprofCase struct {
	name   string
	server *splithttp.Config
	link   string
	path   string // the link's path, when not the server's (a file under it)
}

func xprofCases() []xprofCase {
	nodes := func() *splithttp.Config {
		return &splithttp.Config{Path: "/content/media/", Mode: "packet-up",
			SessionPlacement: "query", SessionKey: "sid", SeqPlacement: "query", SeqKey: "page",
			XPaddingObfsMode: true, XPaddingPlacement: "query", XPaddingKey: "t", XPaddingMethod: "tokenish",
			UplinkHTTPMethod: "POST", UplinkDataPlacement: "body"}
	}
	return []xprofCase{
		// What de4's xh-tw-in serves today (CDN Timeweb): the defaults.
		{"nodes", nodes(), "", "/content/media/stream.m3u8"},
		{"header-meta-header-pad", &splithttp.Config{Path: "/v/", Mode: "packet-up",
			SessionPlacement: "header", SessionKey: "X-Session", SeqPlacement: "header", SeqKey: "X-Seq",
			XPaddingObfsMode: true, XPaddingPlacement: "header", XPaddingHeader: "X-Pad", XPaddingKey: "x_padding", XPaddingMethod: "repeat-x",
			UplinkHTTPMethod: "PUT", UplinkDataPlacement: "body"},
			"&xsp=header&xqp=header&xpp=header&xph=X-Pad&xpm=repeat-x&xpad=100-900&xum=PUT", ""},
		{"cookie-meta-get-header-data", &splithttp.Config{Path: "/img/", Mode: "packet-up",
			SessionPlacement: "cookie", SessionKey: "sess", SeqPlacement: "cookie", SeqKey: "n",
			XPaddingObfsMode: true, XPaddingPlacement: "cookie", XPaddingKey: "pref", XPaddingHeader: "X-Padding", XPaddingMethod: "tokenish",
			UplinkHTTPMethod: "GET", UplinkDataPlacement: "header", UplinkDataKey: "X-Blob", ServerMaxHeaderBytes: 65536},
			"&xsp=cookie&xsk=sess&xqp=cookie&xqk=n&xpp=cookie&xpk=pref&xum=GET&xdp=header&xdk=X-Blob&xdc=2000&xchunk=6", "/img/a.png"},
		{"path-meta-referer-pad-cookie-data", &splithttp.Config{Path: "/s/", Mode: "packet-up",
			SessionPlacement: "path", SeqPlacement: "path",
			XPaddingObfsMode: true, XPaddingPlacement: "queryInHeader", XPaddingHeader: "Referer", XPaddingKey: "q", XPaddingMethod: "tokenish",
			UplinkHTTPMethod: "PATCH", UplinkDataPlacement: "cookie", UplinkDataKey: "c"},
			"&xsp=path&xqp=path&xpp=queryInHeader&xpk=q&xum=PATCH&xdp=cookie&xdk=c&xchunk=4", ""},
		// Header data on Xray's default 8192-byte header cap: the core's
		// default share per request must fit under it.
		{"header-data-default-cap", &splithttp.Config{Path: "/h/", Mode: "packet-up",
			SessionPlacement: "query", SessionKey: "sid", SeqPlacement: "query", SeqKey: "page",
			XPaddingObfsMode: true, XPaddingPlacement: "query", XPaddingKey: "t", XPaddingMethod: "tokenish",
			UplinkHTTPMethod: "POST", UplinkDataPlacement: "header", UplinkDataKey: "X-Data"},
			"&xdp=header", ""},
		{"nodes-extra-headers", nodes(), "&xh=" + url.QueryEscape("Origin:https://cdn.example|X-Requested-With:XMLHttpRequest"), "/content/media/stream.m3u8"},
	}
}

// Every profile the link can name is one Xray's server reads: a flow runs
// both ways through Xray's own splithttp inbound set to the same profile,
// with an uplink large enough to take many requests.
func TestXHTTPProfileAgainstXray(t *testing.T) {
	if raceOn {
		t.Skip("Xray's inbounds do uintptr arithmetic that -race's checkptr rejects")
	}
	for _, c := range xprofCases() {
		t.Run(c.name, func(t *testing.T) {
			sc := serverStream("xhttp", serverTLS(t))
			sc.TransportSettings = []*internet.TransportConfig{{ProtocolName: "splithttp", Settings: xserial.ToTypedMessage(c.server)}}
			port := xrayServe(t, vlessServer(""), sc)
			link := fmt.Sprintf("vless://%s@127.0.0.1:%d?type=xhttp&mode=packet-up&path=%s&xquery=1%s&security=tls&sni=farvater.test&allowInsecure=1#t",
				testUUID, port, url.QueryEscape(first(c.path, c.server.Path)), c.link)
			spec, err := ParseURI(link)
			if err != nil {
				t.Fatal(err)
			}
			w, err := Build(spec)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			dctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			sess, err := w.Dial(dctx)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancelRun := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancelRun()
			echoBig(t, ctx, sess, 96<<10)
		})
	}
}

// echoBig sends n random bytes through a flow to a TCP echo and reads them back.
func echoBig(t *testing.T, ctx context.Context, sess Session, n int) {
	t.Helper()
	port := echoTCP(t)
	data := make([]byte, n)
	rand.Read(data)
	up := make(chan []byte, 64)
	pr, pw := io.Pipe()
	go func() {
		sess.Run(ctx, Target{Host: "127.0.0.1", Port: port}, data[:100], up, pw, nopMeter{})
		pw.Close()
	}()
	go func() {
		for off := 100; off < n; off += 7000 {
			up <- data[off:min(off+7000, n)]
		}
	}()
	got := make([]byte, n)
	if _, err := io.ReadFull(pr, got); err != nil {
		t.Fatalf("echo: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("echo differs")
	}
	close(up)
	go func() { _, _ = io.Copy(io.Discard, pr) }()
}

func TestXQueryProfileRefusesUnknown(t *testing.T) {
	base := "vless://11111111-2222-3333-4444-555555555555@h:443?type=xhttp&security=tls&sni=h&path=%2Fa&mode=packet-up&xquery=1"
	for _, bad := range []string{"&xsp=body", "&xpp=path", "&xpm=zeros", "&xum=DELETE", "&xdp=query", "&xum=GET",
		"&xh=" + url.QueryEscape("Host:evil"), "&xh=" + url.QueryEscape("nocolon")} {
		if _, err := ParseURI(base + bad); err == nil {
			t.Errorf("%s: want refused", bad)
		}
	}
	if _, err := ParseURI(base + "&xum=get&xdp=cookie"); err != nil {
		t.Errorf("GET with cookie data: %v", err)
	}
}

// The defaults keep the wire of the nodes' profile byte for byte in shape:
// session and sequence in the query, a base62 padding, body data, POST.
func TestXQueryProfileDefaultsUnchanged(t *testing.T) {
	x := xqDefaults(XQuerySpec{})
	r := x.request(url.URL{Scheme: "https", Host: "cdn", Path: "/f.m3u8"}, "abc", "3", []byte("hi"))
	u, _ := url.Parse(r.url)
	if u.Path != "/f.m3u8" || u.Query().Get("sid") != "abc" || u.Query().Get("page") != "3" || strings.Trim(u.Query().Get("t"), base62) != "" {
		t.Fatalf("url %s", r.url)
	}
	if x.UpMethod != "POST" || string(r.body) != "hi" || r.header.Get("Content-Type") != "application/octet-stream" ||
		r.header.Get("Referer") != "" || r.header.Get("Cookie") != "" {
		t.Fatalf("request %+v", r)
	}
}
