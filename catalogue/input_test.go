package catalogue

import (
	"encoding/base64"
	"net/url"
	"testing"
)

func TestResolveFindsTheSubscriptionLink(t *testing.T) {
	sub := "https://sub.example.com/s/abc?x=1&y=2"
	zwsp, bom := string(rune(0x200b)), string(rune(0xfeff))
	for _, in := range []string{
		sub,
		" " + zwsp + sub + bom + "\n",
		"HTTPS://sub.example.com/s/abc?x=1&y=2",
		"sub.example.com/s/abc?x=1&y=2",
		"Ваша подписка: " + sub + ". Она обновляется сама.",
		"«" + sub + "»",
		"Подписка: " + sub + " Помощь: https://help.example.com/faq",
		"happ://add/" + sub,
		"v2raytun://import/" + sub,
		"streisand://import/" + sub + "#My%20VPN",
		"hiddify://import/" + sub + "#VPN",
		"app://import/" + url.QueryEscape(sub) + "#VPN",
		"v2rayng://install-config?url=" + url.QueryEscape(sub) + "&name=VPN",
		"sing-box://import-remote-profile?url=" + url.QueryEscape(sub) + "#VPN",
		"karing://install-config?url=" + url.QueryEscape(sub),
		"clash://install-config?url=" + url.QueryEscape(sub),
		"loon://import?sub=" + url.QueryEscape(sub),
		"foxray://yiguo.dev/sub/add/?url=" + url.QueryEscape(sub) + "#VPN",
		"sub://" + base64.StdEncoding.EncodeToString([]byte(sub)) + "#VPN",
		"shadowrocket://add/sub://" + base64.URLEncoding.EncodeToString([]byte(sub)) + "?remark=VPN",
	} {
		if got := Resolve(in); got != sub {
			t.Errorf("Resolve(%q) = %q, want the link", in, got)
		}
	}
}

func TestResolveKeepsTheCatalogueText(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte(l1 + "\n" + l2))
	js := `{"v":1,"paths":[{"uri":"` + l1 + `"}],"probe_urls":["https://example.org/256k"]}`
	for _, c := range []struct{ in, want string }{
		{l1, l1},
		{"\n " + l1 + "\n" + l2 + "\n", l1 + "\n" + l2},
		{"Сервер:\n" + l1 + "\n", "Сервер:\n" + l1},
		{"Ключ: " + l1 + " — вставьте в приложение.", l1},
		{"Ключи: " + l1 + ", " + l2 + ".", l1 + "\n" + l2},
		{b64, b64},
		{js, js},
		{"sub.example.com", "sub.example.com"},
		{"просто текст", "просто текст"},
		{"", ""},
	} {
		if got := Resolve(c.in); got != c.want {
			t.Errorf("Resolve(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// What Resolve keeps, Parse reads.
	for _, in := range []string{"Ключи: " + l1 + ", " + l2 + ".", b64, js} {
		if _, err := Parse([]byte(Resolve(in))); err != nil {
			t.Errorf("Parse(Resolve(%q)): %v", in, err)
		}
	}
}
