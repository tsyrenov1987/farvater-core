package wire

import (
	"net/url"
	"strings"
	"testing"
)

func TestXQueryLinkAndURL(t *testing.T) {
	link := "vless://11111111-2222-3333-4444-555555555555@cdn.example:443?type=xhttp&security=tls&sni=cdn.example" +
		"&path=%2Fcontent%2Fmedia%2Fstream.m3u8%3Fv%3D2&mode=packet-up&xquery=1&xsk=s&xqk=n&xpad=10-20&xchunk=64&xinfl=2#x"
	spec, err := ParseURI(link)
	if err != nil {
		t.Fatal(err)
	}
	if !spec.XQuery || spec.XQ.SessionKey != "s" || spec.XQ.SeqKey != "n" || spec.XQ.PadMin != 10 || spec.XQ.PadMax != 20 ||
		spec.XQ.ChunkKiB != 64 || spec.XQ.InFlight != 2 {
		t.Fatalf("knobs: %+v", spec.XQ)
	}
	path, query := splitXHTTPPath(spec.Path)
	x := xqDefaults(spec.XQ)
	if x.PadKey != "t" || x.ContentType == "" {
		t.Fatalf("defaults: %+v", x)
	}
	u, _ := url.Parse(x.url(url.URL{Scheme: "https", Host: "cdn.example", Path: path, RawQuery: query}, "abc", "7"))
	if u.Path != "/content/media/stream.m3u8" {
		t.Fatalf("path %q: a file path keeps no trailing slash", u.Path)
	}
	q := u.Query()
	if q.Get("v") != "2" || q.Get("s") != "abc" || q.Get("n") != "7" {
		t.Fatalf("query %v", q)
	}
	if p := q.Get("t"); len(p) < 10 || len(p) > 20 || strings.Trim(p, base62) != "" {
		t.Fatalf("padding %q", p)
	}
	if strings.Contains(u.String(), "XXXXX") {
		t.Fatal("no X runs")
	}
	x.PadKey = "-"
	if u2, _ := url.Parse(x.url(url.URL{Path: path}, "abc", "")); u2.Query().Has("t") || u2.Query().Has("n") {
		t.Fatalf("no padding, no seq on the GET: %v", u2.Query())
	}
}

func TestXQueryOffByDefault(t *testing.T) {
	spec, err := ParseURI("vless://11111111-2222-3333-4444-555555555555@h:443?type=xhttp&security=tls&sni=h&path=%2Fa")
	if err != nil {
		t.Fatal(err)
	}
	if spec.XQuery {
		t.Fatal("xquery must be opt-in")
	}
}
