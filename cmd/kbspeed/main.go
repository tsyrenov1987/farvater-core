// Command kbspeed is the far end kbbench measures against when a public
// speed test refuses the node's address: GET /__down?bytes=N answers N bytes,
// POST /__up reads the body and says how much came.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
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
		for n > 0 {
			m := min(n, int64(len(buf)))
			if _, err := w.Write(buf[:m]); err != nil {
				return
			}
			n -= m
		}
	})
	http.HandleFunc("/__up", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		fmt.Fprintln(w, n)
	})
	log.Fatal(http.ListenAndServe(*listen, nil))
}
