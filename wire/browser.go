package wire

import (
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// This file gives our HTTP transports (WebSocket, gRPC, XHTTP) the request
// headers a Chrome request carries, so a tunnel request reads like an
// ordinary browser one. The values track Chrome; keep them current, or the
// set drifts from real Chrome and stands out.

// chromeMajor is the major version of Chrome stable by the host's clock.
var chromeMajor = sync.OnceValue(func() int { return chromeMajorAt(time.Now()) })

// chromeMajorAt: Chrome 157 reached stable on 2026-11-03, and a new major
// has come every two weeks since Chrome 153 (2026-09-08). A clock behind
// that day gives 157; one far ahead is held to a year past it, so a wrong
// clock cannot name a Chrome that does not exist.
func chromeMajorAt(now time.Time) int {
	const base = 157
	baseDay := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	steps := int(now.Sub(baseDay) / (14 * 24 * time.Hour))
	return base + min(max(steps, 0), 26)
}

func chromeUA() string {
	v := strconv.Itoa(chromeMajor())
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + v + ".0.0.0 Safari/537.36"
}

func chromeUACH() string { return chromeUACHFor(chromeMajor()) }

// chromeUACHFor is Sec-CH-UA as Chrome of major v sends it. Chromium makes
// the GREASE brand and the order of the three brands from the major version
// (user_agent_utils.cc, seed = major), so one version always sends the same
// string: Chrome 133 sends "Not(A:Brand";v="99", "Google Chrome";v="133",
// "Chromium";v="133". A random order per request is no Chrome's.
func chromeUACHFor(v int) string {
	chars := [...]string{" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"}
	greaseVersions := [...]string{"8", "99", "24"}
	orders := [6][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	vs := strconv.Itoa(v)
	in := [3]string{
		`"Not` + chars[v%len(chars)] + "A" + chars[(v+1)%len(chars)] + `Brand";v="` + greaseVersions[v%len(greaseVersions)] + `"`,
		`"Chromium";v="` + vs + `"`,
		`"Google Chrome";v="` + vs + `"`,
	}
	var out [3]string
	for i, at := range orders[v%len(orders)] {
		out[at] = in[i]
	}
	return out[0] + ", " + out[1] + ", " + out[2]
}

// browserHeaders adds the headers Chrome sends, for the request variant
// "ws" (a WebSocket upgrade), "fetch" (an XHTTP/gRPC request), "navigate"
// (opening a page) or an asset the page loads: "style", "script", "image",
// "favicon". Only headers not already set are added.
func browserHeaders(h http.Header, variant string) {
	setIfAbsent(h, "User-Agent", chromeUA())
	setIfAbsent(h, "Sec-CH-UA", chromeUACH())
	setIfAbsent(h, "Sec-CH-UA-Mobile", "?0")
	setIfAbsent(h, "Sec-CH-UA-Platform", `"Windows"`)
	setIfAbsent(h, "Accept-Language", "en-US,en;q=0.9")
	switch variant {
	case "ws":
		setIfAbsent(h, "Sec-Fetch-Mode", "websocket")
		setIfAbsent(h, "Sec-Fetch-Dest", "empty")
		setIfAbsent(h, "Sec-Fetch-Site", "same-origin")
		setIfAbsent(h, "Cache-Control", "no-cache")
		setIfAbsent(h, "Pragma", "no-cache")
		setIfAbsent(h, "Accept", "*/*")
	case "fetch":
		setIfAbsent(h, "Sec-Fetch-Mode", "cors")
		setIfAbsent(h, "Sec-Fetch-Dest", "empty")
		setIfAbsent(h, "Sec-Fetch-Site", "same-origin")
		setIfAbsent(h, "Priority", "u=1, i")
		setIfAbsent(h, "Cache-Control", "no-cache")
		setIfAbsent(h, "Pragma", "no-cache")
		setIfAbsent(h, "Accept", "*/*")
	case "navigate":
		setIfAbsent(h, "Upgrade-Insecure-Requests", "1")
		setIfAbsent(h, "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		setIfAbsent(h, "Sec-Fetch-Site", "none")
		setIfAbsent(h, "Sec-Fetch-Mode", "navigate")
		setIfAbsent(h, "Sec-Fetch-User", "?1")
		setIfAbsent(h, "Sec-Fetch-Dest", "document")
		setIfAbsent(h, "Accept-Encoding", chromeAcceptEncoding)
		setIfAbsent(h, "Priority", "u=0, i")
	case "style", "script", "image", "favicon":
		const img = "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
		a := map[string][3]string{
			"style":   {"text/css,*/*;q=0.1", "u=0", "style"},
			"script":  {"*/*", "u=1", "script"},
			"image":   {img, "u=2, i", "image"},
			"favicon": {img, "u=1, i", "image"},
		}[variant]
		setIfAbsent(h, "Accept", a[0])
		setIfAbsent(h, "Sec-Fetch-Site", "same-origin")
		setIfAbsent(h, "Sec-Fetch-Mode", "no-cors")
		setIfAbsent(h, "Sec-Fetch-Dest", a[2])
		setIfAbsent(h, "Accept-Encoding", chromeAcceptEncoding)
		setIfAbsent(h, "Priority", a[1])
	}
}

// chromeAcceptEncoding is what Chrome asks for. Setting it turns off the
// http2 Transport's own gzip handling, so only requests whose body we do not
// read as a stream of our own (a page, an asset) or whose server never
// compresses (kilvater's tunnel) carry it.
const chromeAcceptEncoding = "gzip, deflate, br, zstd"

func setIfAbsent(h http.Header, k, v string) {
	if h.Get(k) == "" {
		h.Set(k, v)
	}
}

// mrandN is a non-cryptographic int in [0, n); used for padding lengths,
// where only variety matters.
func mrandN(n int) int { return rand.IntN(n) }
