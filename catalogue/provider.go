package catalogue

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Provider is what a subscription's provider says about the account, in the
// response headers other clients read too (Happ, Hiddify, v2RayTun, Karing):
// so any provider that already fills them shows the same in Farvater.
//
//	subscription-userinfo   upload=; download=; total=; expire= (bytes, unix seconds)
//	profile-title           the subscription's name
//	profile-update-interval hours between refreshes
//	support-url             the provider's support
//	profile-web-page-url    the provider's site
//	announce                a notice for the user
//	sub-expire-button-link  where the account is renewed
//	sub-info-text, sub-info-color, sub-info-button-text, sub-info-button-link
//	                        a coloured notice with an optional button
//	invite-url              Farvater's addition: the account's invite link,
//	                        shown as a QR code for a friend to scan
//	invite-bonus            Farvater's addition: days the next friend brings
//	access-code             Farvater's addition: the account's code, for
//	                        paying and for support
//	month-traffic           Farvater's addition: used=; cap=; slow=1 (bytes
//	                        this month, the cap before the speed drops)
//	white-traffic           Farvater's addition: used=; cap=; paused=1 (the
//	                        same for the entries that work under whitelists)
//	renew-url               Farvater's addition: where the account is
//	                        renewed, when sub-expire-button-link is absent
//
// Text may be plain ASCII or "base64:" and the base64 of UTF-8. Links must be
// https. A header that breaks these rules is left out, not guessed at.
type Provider struct {
	Title          string `json:"title,omitempty"`
	Upload         int64  `json:"upload,omitempty"`
	Download       int64  `json:"download,omitempty"`
	Total          int64  `json:"total,omitempty"`  // 0: no cap
	Expire         int64  `json:"expire,omitempty"` // 0: no end
	UpdateHours    int    `json:"update_hours,omitempty"`
	SupportURL     string `json:"support_url,omitempty"`
	WebURL         string `json:"web_url,omitempty"`
	Announce       string `json:"announce,omitempty"`
	RenewURL       string `json:"renew_url,omitempty"`
	InfoText       string `json:"info_text,omitempty"`
	InfoColor      string `json:"info_color,omitempty"` // red, blue or green
	InfoButtonText string `json:"info_button_text,omitempty"`
	InfoButtonURL  string `json:"info_button_url,omitempty"`
	InviteURL      string `json:"invite_url,omitempty"`
	InviteDays     int    `json:"invite_days,omitempty"`
	Code           string `json:"code,omitempty"`
	Month          *Meter `json:"month,omitempty"`
	White          *Meter `json:"white,omitempty"`
}

// Meter is a monthly allowance: bytes used, the cap (0: none) and whether
// it is spent (the speed dropped, or the entries are paused).
type Meter struct {
	Used  int64 `json:"used"`
	Cap   int64 `json:"cap"`
	Spent bool  `json:"spent,omitempty"`
}

// ProviderFrom reads the headers; nil when the provider sent none of them.
func ProviderFrom(h http.Header) *Provider {
	p := Provider{
		Title:          headerText(h.Get("profile-title"), 60),
		SupportURL:     httpsOnly(h.Get("support-url")),
		WebURL:         httpsOnly(h.Get("profile-web-page-url")),
		Announce:       headerText(h.Get("announce"), 400),
		RenewURL:       httpsOnly(h.Get("sub-expire-button-link")),
		InfoText:       headerText(h.Get("sub-info-text"), 200),
		InfoButtonText: headerText(h.Get("sub-info-button-text"), 25),
		InfoButtonURL:  httpsOnly(h.Get("sub-info-button-link")),
		InviteURL:      httpsOnly(h.Get("invite-url")),
		Code:           accessCode(h.Get("access-code")),
		Month:          meter(h.Get("month-traffic"), "slow"),
		White:          meter(h.Get("white-traffic"), "paused"),
	}
	if p.RenewURL == "" {
		p.RenewURL = httpsOnly(h.Get("renew-url"))
	}
	if n, err := strconv.Atoi(strings.TrimSpace(h.Get("invite-bonus"))); err == nil && n > 0 && n <= 3650 {
		p.InviteDays = n
	}
	p.UpdateHours, _ = strconv.Atoi(strings.TrimSpace(h.Get("profile-update-interval")))
	if p.UpdateHours < 0 {
		p.UpdateHours = 0
	}
	for k, n := range pairs(h.Get("subscription-userinfo")) {
		switch k {
		case "upload":
			p.Upload = n
		case "download":
			p.Download = n
		case "total":
			p.Total = n
		case "expire":
			p.Expire = n
		}
	}
	if p.InfoText != "" {
		switch c := strings.ToLower(strings.TrimSpace(h.Get("sub-info-color"))); c {
		case "red", "green":
			p.InfoColor = c
		default:
			p.InfoColor = "blue"
		}
	}
	if p == (Provider{}) {
		return nil
	}
	return &p
}

// pairs reads "a=1; b=2" into lower-case keys and non-negative numbers.
func pairs(v string) map[string]int64 {
	out := map[string]int64{}
	for _, kv := range strings.Split(v, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil || n < 0 {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(k))] = n
	}
	return out
}

// meter reads "used=; cap=; <flag>=1"; nil without used.
func meter(v, flag string) *Meter {
	kv := pairs(v)
	used, ok := kv["used"]
	if !ok {
		return nil
	}
	return &Meter{Used: used, Cap: kv["cap"], Spent: kv[flag] == 1}
}

// accessCode keeps a code of letters, digits and dashes; anything else is dropped.
func accessCode(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 40 {
		return ""
	}
	for _, r := range v {
		if !(r == '-' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return ""
		}
	}
	return v
}

// headerText decodes a "base64:" value and keeps at most max characters of
// printable text; anything else is dropped.
func headerText(v string, max int) string {
	v = strings.TrimSpace(v)
	if rest, ok := strings.CutPrefix(v, "base64:"); ok {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
		if err != nil {
			b, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(rest), "="))
		}
		if err != nil || !utf8.Valid(b) {
			return ""
		}
		v = strings.TrimSpace(string(b))
	}
	v = strings.Map(func(r rune) rune {
		if r == '\n' || r >= ' ' && r != 0x7f {
			return r
		}
		return -1
	}, v)
	if r := []rune(v); len(r) > max {
		v = string(r[:max])
	}
	return v
}

func httpsOnly(v string) string {
	v = strings.TrimSpace(v)
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return ""
	}
	return v
}
