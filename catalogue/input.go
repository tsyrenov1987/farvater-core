package catalogue

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/tsyrenov1987/farvater-core/wire"
)

// invisible are the characters copying from messengers and web pages leaves in
// text: the soft hyphen, zero-width spaces and joiners, direction marks, the
// word joiner and the byte-order mark. None belongs in a link or in base64.
var invisible = strings.NewReplacer(
	"\u00ad", "", "\u200b", "", "\u200c", "", "\u200d", "", "\u200e", "", "\u200f", "", "\u2060", "", "\ufeff", "",
)

// wrapping is what a message puts around a link: quotes, brackets and the
// punctuation that ends a sentence.
const wrapping = `"'«»“”„()[]<>.,;:!?`

// bareLink is a subscription link pasted without its scheme: a domain, then a path.
var bareLink = regexp.MustCompile(`^[\p{L}\p{N}.-]+\.\p{L}{2,}(:\d+)?/\S*$`)

// Resolve turns what a person pasted where a catalogue goes into the source a
// client keeps: a subscription URL to fetch, or the catalogue text itself
// (JSON, share links, base64) for Parse. It finds the link as it is, without
// its scheme, inside another client's import link (a url= or sub= parameter, a
// link after the path, Shadowrocket's sub://base64) or among the words of a
// message, and share links among those words too. Text it doesn't recognise
// comes back trimmed, for Parse to say what is wrong with it.
func Resolve(input string) string {
	t := strings.TrimSpace(invisible.Replace(input))
	if t == "" || t[0] == '{' || t[0] == '[' || shareLines(t) {
		return t
	}
	words := strings.Fields(t)
	var links []string
	for _, w := range words {
		for _, c := range []string{strings.Trim(w, wrapping), w} {
			if _, err := wire.ParseURI(c); err == nil {
				links = append(links, c)
				break
			}
		}
	}
	if len(links) > 0 {
		return strings.Join(links, "\n")
	}
	for _, w := range words {
		if u := subscriptionIn(strings.Trim(w, wrapping)); u != "" {
			return u
		}
	}
	if bareLink.MatchString(t) {
		return "https://" + t
	}
	return t
}

// shareLines reports whether some line of t is a share link Parse runs.
func shareLines(t string) bool {
	for _, l := range strings.Split(t, "\n") {
		if _, err := wire.ParseURI(l); err == nil {
			return true
		}
	}
	return false
}

// subscriptionIn returns the http(s) link one pasted word is or carries:
// happ://add/<link>, v2rayng://install-config?url=<link>,
// sing-box://import-remote-profile?url=<link>#name, sub://<base64 link> and
// the like. "" when there is none.
func subscriptionIn(w string) string {
	i := strings.Index(w, "://")
	if i <= 0 {
		return ""
	}
	if l := httpLink(w); l != "" {
		return l
	}
	if u, err := url.Parse(w); err == nil {
		q := u.Query()
		for _, k := range []string{"url", "sub"} {
			if l := httpLink(q.Get(k)); l != "" {
				return l
			}
		}
	}
	rest := w[i+3:]
	if j := firstIndex(strings.ToLower(rest), "https://", "http://"); j >= 0 {
		return httpLink(cutAt(rest[j:], "#"))
	}
	if j := firstIndex(strings.ToLower(rest), "https%3a%2f%2f", "http%3a%2f%2f"); j >= 0 {
		if s, err := url.PathUnescape(cutAt(rest[j:], "#")); err == nil {
			return httpLink(s)
		}
	}
	if j := strings.Index(strings.ToLower(w), "sub://"); j >= 0 {
		if b, err := decodeB64(cutAt(w[j+6:], "#?&")); err == nil {
			return httpLink(strings.TrimSpace(string(b)))
		}
	}
	return ""
}

// httpLink returns s with its scheme in lower case when s is an http(s) URL
// with a host, else "".
func httpLink(s string) string {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return u.Scheme + s[len(u.Scheme):]
}

// firstIndex is the earliest index in s of any of subs, or -1.
func firstIndex(s string, subs ...string) int {
	first := -1
	for _, sub := range subs {
		if i := strings.Index(s, sub); i >= 0 && (first < 0 || i < first) {
			first = i
		}
	}
	return first
}

// cutAt returns s up to the first of the bytes in stops.
func cutAt(s, stops string) string {
	if i := strings.IndexAny(s, stops); i >= 0 {
		return s[:i]
	}
	return s
}
