// ja4cap listens on a TCP port and prints the JA4 of every TLS ClientHello
// that arrives, then closes the connection. Point a browser at it to take
// the fingerprint the core's fp= profiles are held to:
//
//	go run ./tools/ja4cap -listen 127.0.0.1:8443
//	chrome --host-resolver-rules="MAP ja4.test 127.0.0.1" https://ja4.test:8443/
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/tsyrenov1987/farvater-core/ja4"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:8443", "address to listen on")
	flag.Parse()
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			msg, err := ja4.ReadClientHello(c)
			if err != nil {
				return
			}
			fp, raw, err := ja4.Of(msg)
			if err != nil {
				return
			}
			fmt.Printf("%s\n%s\n\n", fp, raw)
		}()
	}
}
