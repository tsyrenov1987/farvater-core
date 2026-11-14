package service

import (
	"errors"
	"regexp"
	"strings"
)

// The window runs as an ordinary user and the service as the machine, so what
// the window may ask the service to fetch is narrow: Orden's codes and Orden's
// subscription links. A local program could otherwise point the whole
// machine's traffic at its own server.

const subscription = "https://joinorden.com/hsub/ORDEN-"

var (
	invisible = regexp.MustCompile(`[\x{00AD}\x{200B}-\x{200F}\x{2060}\x{FEFF}]`)
	longDash  = regexp.MustCompile(`[\x{2010}-\x{2015}\x{2212}]`)
	// Cyrillic letters that look like Latin ones, as on a Russian layout.
	twins = strings.NewReplacer(
		"\u0410", "A", "\u0412", "B", "\u0415", "E", "\u041A", "K", "\u041C", "M", "\u041D", "H",
		"\u041E", "O", "\u0420", "P", "\u0421", "C", "\u0422", "T", "\u0423", "Y", "\u0425", "X",
	)
	aloneCode = regexp.MustCompile(`^(?:ORDEN[-_ ]*)?([0-9A-Z]{5})[-_ ]*([0-9A-Z]{5})$`)
	ordenURL  = regexp.MustCompile(`(?i)^https://(?:www\.)?(?:joinorden\.com|myorden\.ru|viporden\.online)(/\S*)$`)
	subPath   = regexp.MustCompile(`(?i)^/(?:hsub|sub)/[^/?#\s]+$`)
	anySub    = regexp.MustCompile(`(?i)^/(?:hsub|sub)/`)
	httpCode  = regexp.MustCompile(`HTTP (\d{3})`)
)

var errNotOrden = errors.New("На компьютере работают только код доступа и ссылка Orden.")

// Source turns what the window sent into the link the service keeps, or
// refuses it.
func Source(input string) (string, error) {
	t := strings.TrimSpace(invisible.ReplaceAllString(input, ""))
	if m := ordenURL.FindStringSubmatch(t); m != nil && subPath.MatchString(m[1]) {
		return t, nil
	}
	s := twins.Replace(longDash.ReplaceAllString(strings.ToUpper(t), "-"))
	if m := aloneCode.FindStringSubmatch(s); m != nil && m[1] != "ORDEN" {
		return subscription + m[1] + "-" + m[2], nil
	}
	return "", errNotOrden
}

// plainDoor serves the same catalogue under a name without the brand in it, so
// the first hostname a client shows the network does not say whose client it is.
const plainDoor = "https://cdn2.cdn-tvzvezda-ru.ru/api"

// mirrors lists where to fetch a subscription from, in order (AccessCode.mirrors
// on the phones).
func mirrors(source string) []string {
	m := ordenURL.FindStringSubmatch(strings.TrimSpace(source))
	if m == nil {
		return []string{source}
	}
	var out []string
	if anySub.MatchString(m[1]) {
		out = append(out, plainDoor+m[1], "https://viporden.online"+m[1])
	}
	return append(out, "https://myorden.ru"+m[1], "https://joinorden.com"+m[1])
}

// settled says a mirror's failure is the server's answer about the code,
// which every other mirror would repeat (AccessCode.settled).
func settled(err error) bool {
	m := httpCode.FindStringSubmatch(err.Error())
	if m == nil {
		return false
	}
	n := 0
	for _, c := range m[1] {
		n = n*10 + int(c-'0')
	}
	return n >= 400 && n <= 499 && n != 408 && n != 425 && n != 429
}
