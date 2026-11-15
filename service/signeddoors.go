package service

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tsyrenov1987/farvater-core/wire"
)

// Orden's signed list of doors, the one its own apps read: a TXT record at
// signedName (DoorSpec's txt) holding base64url("v1|<https origins,
// comma-separated>|<unix time>") + "." + base64url(ECDSA P-256 SHA-256
// signature, DER), made offline with the key whose public half is signedKey
// (DoorSpec's key). When every door and mirror built in is cut, the doors
// signed since still reach the catalogue without a new build. A resolver
// cannot hand out its own doors: only the offline key makes a list that
// verifies.
//
// A list older than this is not taken (it is re-signed well within it), nor
// one from more than a day ahead.
const signedMaxAge = 90 * 24 * time.Hour

// The resolvers are asked by address and over HTTPS, so reading the list
// depends neither on the system's resolver nor on any of Orden's names.
var signedResolvers = []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/resolve"}

// SignedDoors returns the origins of Orden's signed list, or nil when no
// resolver gives a list that verifies.
func SignedDoors() []string {
	if signedName == "" || signedKey == "" {
		return nil
	}
	der, _ := base64.StdEncoding.DecodeString(signedKey)
	k, err := x509.ParsePKIXPublicKey(der)
	pub, ok := k.(*ecdsa.PublicKey)
	if err != nil || !ok {
		return nil
	}
	// Chrome's TLS to the resolvers, not Go's (F-133).
	cl := &http.Client{Timeout: 8 * time.Second, Transport: &wire.BrowserTransport{}}
	for _, r := range signedResolvers {
		if doors := verifyDoors(txt(cl, r, signedName), pub, time.Now()); len(doors) > 0 {
			return doors
		}
	}
	return nil
}

// txt is the TXT record name holds, its strings joined, as DNS JSON from the
// resolver at endpoint; "" when there is none.
func txt(cl *http.Client, endpoint, name string) string {
	req, err := http.NewRequest(http.MethodGet, endpoint+"?name="+url.QueryEscape(name)+"&type=TXT", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := cl.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var d struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		}
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&d) != nil {
		return ""
	}
	// A long record comes split into quoted strings: "a" "b".
	unquote := strings.NewReplacer(`"`, "", " ", "")
	var b strings.Builder
	for _, a := range d.Answer {
		if a.Type == 16 {
			b.WriteString(unquote.Replace(a.Data))
		}
	}
	return b.String()
}

// verifyDoors returns the origins in blob when pub signed it and it is fresh
// at now; nil otherwise.
func verifyDoors(blob string, pub *ecdsa.PublicKey, now time.Time) []string {
	p, s, ok := strings.Cut(blob, ".")
	if !ok {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(p, "="))
	if err != nil {
		return nil
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil
	}
	h := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(pub, h[:], sig) {
		return nil
	}
	parts := strings.Split(string(payload), "|")
	if len(parts) != 3 || parts[0] != "v1" {
		return nil
	}
	ts, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return nil
	}
	if at := time.Unix(ts, 0); at.Before(now.Add(-signedMaxAge)) || at.After(now.Add(24*time.Hour)) {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, o := range strings.Split(parts[1], ",") {
		o = strings.TrimRight(strings.TrimSpace(o), "/")
		u, err := url.Parse(o)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.User != nil || len(o) > 200 {
			continue
		}
		if !seen[u.Host] {
			seen[u.Host] = true
			out = append(out, "https://"+u.Host)
		}
	}
	return out
}

// signedMirrors lists the source's catalogue at the doors of the origins
// doors gives whose hosts none of tried used: a door serves Orden's API under
// /api, like the plain one. doors is asked only for Orden's subscription, so
// another provider's link never makes the app look Orden's list up.
func signedMirrors(source string, doors func() []string, tried []string) []string {
	m := ordenURL.FindStringSubmatch(strings.TrimSpace(source))
	if m == nil || !anySub.MatchString(m[1]) {
		return nil
	}
	used := map[string]bool{}
	for _, t := range tried {
		if u, err := url.Parse(t); err == nil {
			used[strings.ToLower(u.Host)] = true
		}
	}
	var out []string
	for _, o := range doors() {
		u, err := url.Parse(o)
		if err != nil || used[strings.ToLower(u.Host)] {
			continue
		}
		used[strings.ToLower(u.Host)] = true
		out = append(out, "https://"+u.Host+"/api"+m[1])
	}
	return out
}
