// Command kbspeed is the far end kbbench measures against when a public
// speed test refuses the node's address: GET /__down?bytes=N[&rate=R] answers N bytes (at R a second),
// POST /__up reads the body and says how much came.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"
)

func main() {
	listen := flag.String("listen", ":18099", "address to serve on")
	flag.Parse()
	buf := make([]byte, 64<<10)
	for i := range buf {
		buf[i] = byte(i*131 + i>>8)
	}
	http.HandleFunc("/__down", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		if n <= 0 || n > 1<<30 {
			http.Error(w, "bytes", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		rate, _ := strconv.ParseFloat(r.URL.Query().Get("rate"), 64) // bytes a second; 0 = as fast as it goes
		piece := int64(len(buf))
		if rate > 0 {
			piece = 8 << 10
		}
		start, sent := time.Now(), int64(0)
		for n > 0 {
			m := min(n, piece)
			if _, err := w.Write(buf[:m]); err != nil {
				return
			}
			n -= m
			if sent += m; rate > 0 {
				w.(http.Flusher).Flush()
				time.Sleep(time.Until(start.Add(time.Duration(float64(sent) / rate * float64(time.Second)))))
			}
		}
	})
	http.HandleFunc("/__up", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		fmt.Fprintln(w, n)
	})
	log.Fatal(http.ListenAndServe(*listen, nil))
}
