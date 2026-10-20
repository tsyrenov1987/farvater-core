package wire

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/vkturn"
)

func vkturnLink(inner, creds, extra string) string {
	b := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return "vkturn://" + strings.Repeat("ab", 32) + "@203.0.113.7:41641?c=" + b(creds) + "&inner=" + b(inner) + extra + "#de3-vk"
}

const vkInner = "vless://95223f77-13e1-4307-82cd-468b5fef9cc8@203.0.113.7:443?security=reality&encryption=none&pbk=6PamM3w3S6HQ8x9AladlPPAEYYQ8RqWxXGDstBO_BVY&fp=firefox&type=xhttp&path=%2F&mode=stream-one&sni=x13.example.org&sid=b4783439f19bb364#in"

const vkCreds = `[{"address":"193.203.43.15:19302","username":"1792485416:598288602919","password":"p"},{"Address":"90.156.236.78:19302","Username":"1792485400:1","Password":"q"}]`

func TestParseVKTurn(t *testing.T) {
	s, err := ParseURI(vkturnLink(vkInner, vkCreds, "&cu=https%3A%2F%2Fexample.org%2Fvkc%2Ft"))
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != "de3-vk" || s.Kind != KindVLESS || s.Network != "xhttp" || s.Security != "reality" || s.Rail() != "vkturn" || s.HTTPLike() {
		t.Fatalf("spec %+v rail %s", s, s.Rail())
	}
	tr := s.TURN
	if tr.Server != "203.0.113.7:41641" || tr.Target != "127.0.0.1:2090" || tr.CredsURL != "https://example.org/vkc/t" || len(tr.PSK) != 32 {
		t.Fatalf("turn %+v", tr)
	}
	// Both key spellings: the pool on the server writes them capitalised.
	if len(tr.Creds) != 2 || tr.Creds[1].Address != "90.156.236.78:19302" || tr.Creds[1].Password != "q" {
		t.Fatalf("creds %+v", tr.Creds)
	}
	if got := vkturn.Expiry(tr.Creds); !got.Equal(time.Unix(1792485400, 0)) {
		t.Fatalf("expiry %v", got)
	}
}

func TestParseVKTurnRejects(t *testing.T) {
	for name, link := range map[string]string{
		"nested":     vkturnLink(vkturnLink(vkInner, vkCreds, ""), vkCreds, ""),
		"hysteria":   vkturnLink("hysteria2://p@203.0.113.7:443#h", vkCreds, ""),
		"no creds":   vkturnLink(vkInner, "[]", ""),
		"http creds": vkturnLink(vkInner, vkCreds, "&cu=http%3A%2F%2Fexample.org%2Fx"),
		"short key":  strings.Replace(vkturnLink(vkInner, vkCreds, ""), strings.Repeat("ab", 32), "abcd", 1),
	} {
		if _, err := ParseURI(link); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
