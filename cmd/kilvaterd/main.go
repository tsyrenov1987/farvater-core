package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/tsyrenov1987/farvater-core/kilvater"
	"golang.org/x/net/http2"
)

func main() {
	listen := flag.String("listen", ":443", "address to listen on")
	certFile := flag.String("cert", "cert.pem", "TLS certificate file")
	keyFile := flag.String("key", "key.pem", "TLS private key file")
	keysFile := flag.String("keys", "keys.txt", "client keys, one 64-hex line per key")
	decoyDir := flag.String("decoy", "/var/www/html", "static files served to non-tunnel visitors")
	flag.Parse()

	keys, err := readKeys(*keysFile)
	if err != nil {
		log.Fatalf("keys: %v", err)
	}
	log.Printf("loaded %d client key(s)", len(keys))

	srv := &kilvater.Server{
		Verifier: kilvater.NewVerifier(keys),
		Decoy:    http.FileServer(http.Dir(*decoyDir)),
		Logger:   log.Default(),
	}

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
	}

	ln, err := tls.Listen("tcp", *listen, tlsCfg)
	if err != nil {
		log.Fatal(err)
	}

	httpSrv := &http.Server{Handler: srv}
	if err := http2.ConfigureServer(httpSrv, &http2.Server{}); err != nil {
		log.Fatal(err)
	}

	log.Printf("kilvaterd listening on %s", *listen)
	log.Fatal(httpSrv.Serve(ln))
}

func readKeys(path string) ([]kilvater.Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys []kilvater.Key
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		k, err := kilvater.ParseKey(line)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no keys in %s", path)
	}
	return keys, nil
}
