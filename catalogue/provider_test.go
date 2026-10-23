package catalogue

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func b64(s string) string { return "base64:" + base64.StdEncoding.EncodeToString([]byte(s)) }

func TestProviderReadsTheHeadersOtherClientsRead(t *testing.T) {
	h := http.Header{}
	h.Set("subscription-userinfo", "upload=5; download=7; total=1073741824; expire=1760000000")
	h.Set("profile-title", b64("Орден Клуб"))
	h.Set("profile-update-interval", "12")
	h.Set("support-url", "https://myorden.ru/support")
	h.Set("profile-web-page-url", "https://myorden.ru")
	h.Set("announce", b64("Банки — как обычно.\nНе грузит? Другой сервер."))
	h.Set("sub-expire-button-link", "https://myorden.ru/cabinet")
	h.Set("sub-info-text", b64("⏳ Доступ закончится 12.10"))
	h.Set("sub-info-color", "RED")
	h.Set("sub-info-button-text", b64("Продлить"))
	h.Set("sub-info-button-link", "https://myorden.ru/cabinet")
	h.Set("invite-url", "https://myorden.ru/join?ref=AB12CD")
	p := ProviderFrom(h)
	want := Provider{
		Title: "Орден Клуб", Upload: 5, Download: 7, Total: 1 << 30, Expire: 1760000000, UpdateHours: 12,
		SupportURL: "https://myorden.ru/support", WebURL: "https://myorden.ru",
		Announce: "Банки — как обычно.\nНе грузит? Другой сервер.", RenewURL: "https://myorden.ru/cabinet",
		InfoText: "⏳ Доступ закончится 12.10", InfoColor: "red", InfoButtonText: "Продлить",
		InfoButtonURL: "https://myorden.ru/cabinet", InviteURL: "https://myorden.ru/join?ref=AB12CD",
	}
	if p == nil || *p != want {
		t.Fatalf("got %+v\nwant %+v", p, want)
	}
}

func TestProviderDropsWhatBreaksTheRules(t *testing.T) {
	if p := ProviderFrom(http.Header{}); p != nil {
		t.Fatalf("no headers must give nil, got %+v", p)
	}
	h := http.Header{}
	h.Set("support-url", "http://plain.example.com")     // not https
	h.Set("invite-url", "javascript:alert(1)")           // not a link
	h.Set("announce", "base64:@@@")                      // not base64
	h.Set("subscription-userinfo", "upload=x; total=-5") // not numbers
	h.Set("profile-title", "Plain ASCII title")
	p := ProviderFrom(h)
	if p == nil || *p != (Provider{Title: "Plain ASCII title"}) {
		t.Fatalf("got %+v", p)
	}
}

func TestFetchWithProviderReturnsTheHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("subscription-userinfo", "upload=1; download=2; total=0")
		w.Header().Set("invite-url", "https://example.com/i/1")
		w.Write([]byte("vless://u@h:443?security=tls#a"))
	}))
	defer srv.Close()
	body, p, err := FetchWithProvider(srv.URL)
	if err != nil || string(body) == "" || p == nil || p.Download != 2 || p.InviteURL != "https://example.com/i/1" {
		t.Fatalf("body %q provider %+v err %v", body, p, err)
	}
}

func TestProviderReadsFarvatersAccountHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("access-code", "ORDEN-MJM57-VZ1BW")
	h.Set("month-traffic", "used=11; cap=322122547200; slow=1")
	h.Set("white-traffic", "used=3; cap=5368709120")
	h.Set("renew-url", "https://myorden.ru/cabinet")
	h.Set("invite-bonus", "30")
	p := ProviderFrom(h)
	if p == nil || p.Code != "ORDEN-MJM57-VZ1BW" || p.RenewURL != "https://myorden.ru/cabinet" || p.InviteDays != 30 {
		t.Fatalf("got %+v", p)
	}
	if p.Month == nil || *p.Month != (Meter{Used: 11, Cap: 322122547200, Spent: true}) {
		t.Fatalf("month %+v", p.Month)
	}
	if p.White == nil || *p.White != (Meter{Used: 3, Cap: 5368709120}) {
		t.Fatalf("white %+v", p.White)
	}

	h = http.Header{}
	h.Set("profile-title", "T")
	h.Set("sub-expire-button-link", "https://a.example/renew")
	h.Set("renew-url", "https://b.example/renew")
	h.Set("access-code", "<script>")
	h.Set("month-traffic", "cap=5")
	h.Set("invite-bonus", "-3")
	p = ProviderFrom(h)
	if p.RenewURL != "https://a.example/renew" || p.Code != "" || p.Month != nil || p.InviteDays != 0 {
		t.Fatalf("got %+v", p)
	}
}
