package wire

import (
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync"
)

// This file gives our HTTP transports (WebSocket, gRPC, XHTTP) the request
// headers a Chrome request carries, so a tunnel request reads like an
// ordinary browser one. The values track Chrome; keep them current, or the
// set drifts from real Chrome and stands out.

var chromeMajor = sync.OnceValue(func() int {
	// Chrome ships a major version every few weeks. Anchor to a known
	// release and step forward by calendar, so the number stays plausible
	// without a dependency on the exact day.
	const base, baseYear, baseMonth = 133, 2026, 1
	y, m := 2026, 1 // the knowledge cutoff; the host clock may be wrong, so do not trust it to go backward
	months := (y-baseYear)*12 + (m - baseMonth)
	if months < 0 {
		months = 0
	}
	return base + months*2/3
})

func chromeUA() string {
	v := strconv.Itoa(chromeMajor())
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + v + ".0.0.0 Safari/537.36"
}

func chromeUACH() string {
	v := strconv.Itoa(chromeMajor())
	brands := []string{
		`"Not(A:Brand";v="99"`,
		`"Google Chrome";v="` + v + `"`,
		`"Chromium";v="` + v + `"`,
	}
	rand.Shuffle(len(brands), func(i, j int) { brands[i], brands[j] = brands[j], brands[i] })
	return brands[0] + ", " + brands[1] + ", " + brands[2]
}

// browserHeaders adds the headers Chrome sends, for the request variant
// "ws" (a WebSocket upgrade) or "fetch" (an XHTTP/gRPC request). Only
// headers not already set are added.
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
	}
}

func setIfAbsent(h http.Header, k, v string) {
	if h.Get(k) == "" {
		h.Set(k, v)
	}
}

// mrandN is a non-cryptographic int in [0, n); used for padding lengths,
// where only variety matters.
func mrandN(n int) int { return rand.IntN(n) }
