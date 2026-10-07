package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tsyrenov1987/farvater-core/kilvater"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
)

func main() {
	listen := flag.String("listen", ":443", "address to listen on")
	certFile := flag.String("cert", "cert.pem", "TLS certificate file (ignored with -acme)")
	keyFile := flag.String("key", "key.pem", "TLS private key file (ignored with -acme)")
	keysFile := flag.String("keys", "keys.txt", "client keys, one 64-hex line per key")
	decoyDir := flag.String("decoy", "/var/www/html", "static files served to non-tunnel visitors")
	acmeDomain := flag.String("acme", "", "domain to get a Let's Encrypt certificate for (TLS-ALPN-01); empty uses -cert/-key")
	acmeCache := flag.String("acme-cache", "/var/lib/kilvaterd/acme", "directory where autocert stores certificates")
	flag.Parse()

	keys, err := readKeys(*keysFile)
	if err != nil {
		log.Fatalf("keys: %v", err)
	}
	log.Printf("loaded %d client key(s)", len(keys))

	if entries, derr := os.ReadDir(*decoyDir); derr != nil || len(entries) == 0 {
		log.Printf("warning: decoy dir %q is empty or unreadable (%v); visitors without a key see only 404s, which looks nothing like a real site", *decoyDir, derr)
	}

	srv := &kilvater.Server{
		Verifier: kilvater.NewVerifier(keys),
		Decoy:    http.FileServer(http.Dir(*decoyDir)),
		Logger:   log.Default(),
	}

	tlsCfg, err := tlsConfig(*acmeDomain, *acmeCache, *certFile, *keyFile)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}

	ln, err := tls.Listen("tcp", *listen, tlsCfg)
	if err != nil {
		log.Fatal(err)
	}

	httpSrv := &http.Server{
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := http2.ConfigureServer(httpSrv, &http2.Server{IdleTimeout: 120 * time.Second}); err != nil {
		log.Fatal(err)
	}

	log.Printf("kilvaterd listening on %s", *listen)
	log.Fatal(httpSrv.Serve(ln))
}

// tlsConfig builds the listener's TLS config: a Let's Encrypt certificate
// through autocert when a domain is given, otherwise a static certificate from
// disk. Both advertise h2. The autocert path keeps TLS 1.2 open (TLS-ALPN-01
// validation needs it, and a real site accepts 1.2); the static path stays at
// TLS 1.3.
func tlsConfig(domain, cache, certFile, keyFile string) (*tls.Config, error) {
	if domain != "" {
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domain),
			Cache:      autocert.DirCache(cache),
		}
		// m.TLSConfig sets GetCertificate and NextProtos (h2, http/1.1,
		// acme-tls/1) and leaves the minimum version at the 1.2 default.
		return m.TLSConfig(), nil
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
	}, nil
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
