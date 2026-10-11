package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tsyrenov1987/farvater-core/kilvater"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// version is set at release build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	listen := flag.String("listen", ":443", "address to listen on")
	certFile := flag.String("cert", "cert.pem", "TLS certificate file (ignored with -acme)")
	keyFile := flag.String("key", "key.pem", "TLS private key file (ignored with -acme)")
	keysFile := flag.String("keys", "keys.txt", "v1 client keys, one 64-hex line per key (optional if -master is set)")
	masterFile := flag.String("master", "", "master key file (64 hex) enabling v2 derived keys; empty disables v2")
	revokedFile := flag.String("revoked", "", "revoked v2 key ids, one 16-hex line each, '#' comments (reloaded on SIGHUP)")
	decoyDir := flag.String("decoy", "/var/www/html", "static files served to non-tunnel visitors")
	acmeDomain := flag.String("acme", "", "domain to get a Let's Encrypt certificate for (TLS-ALPN-01); empty uses -cert/-key")
	acmeCache := flag.String("acme-cache", "/var/lib/kilvaterd/acme", "directory where autocert stores certificates")
	allowPrivate := flag.Bool("allow-private", false, "let clients reach loopback, private and link-local addresses (off: only public addresses)")
	padMode := flag.String("pad", "moderate", "downstream traffic padding: off | moderate | heavy (shapes record sizes so a tunnel looks less like one bulk transfer)")
	h2cMode := flag.Bool("h2c", false, "serve cleartext HTTP/2 for a TLS-terminating proxy (nginx/Caddy) in front; -listen may be unix:/path, and -cert/-key/-acme are ignored")
	genKey := flag.Bool("genkey", false, "print a new random client key and exit")
	genMaster := flag.Bool("genmaster", false, "print a new random master key and exit")
	issue := flag.String("issue", "", "with -master: print the key id and derived key for this subscriber id, and exit")
	metricsAddr := flag.String("metrics", "", "serve Prometheus metrics on this address (e.g. 127.0.0.1:9900); empty disables it; keep it on the loopback or a management overlay, never public")
	maxBytesPerKey := flag.Int64("max-bytes-per-key", 0, "refuse a key's new streams once it has carried this many payload bytes up+down; 0 is no limit")
	maxStreamsPerKey := flag.Int64("max-streams-per-key", 0, "cap a key's concurrent streams; 0 is no limit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("kilvaterd", version)
		return
	}
	if *genKey || *genMaster {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(b))
		return
	}
	if *issue != "" {
		if *masterFile == "" {
			log.Fatal("-issue needs -master")
		}
		master, err := readMaster(*masterFile)
		if err != nil {
			log.Fatalf("master: %v", err)
		}
		id := kilvater.KeyIDFor(master, []byte(*issue))
		k := kilvater.DeriveKey(master, id)
		// k[:] prints the real key bytes; %x on a Key would hit its redacting
		// String, which is exactly what we must bypass here to hand out the key.
		fmt.Printf("kid=%s key=%s\n", id, hex.EncodeToString(k[:]))
		return
	}

	cfg, err := loadVerifierConfig(*keysFile, *masterFile, *revokedFile)
	if err != nil {
		log.Fatalf("keys: %v", err)
	}
	log.Printf("loaded %d v1 key(s), master=%v, %d revoked", len(cfg.Keys), cfg.Master != nil, len(cfg.Revoked))

	if entries, derr := os.ReadDir(*decoyDir); derr != nil || len(entries) == 0 {
		log.Printf("warning: decoy dir %q is empty or unreadable (%v); visitors without a key see only 404s, which looks nothing like a real site", *decoyDir, derr)
	}

	verifier := kilvater.NewVerifierConfig(cfg)
	metrics := kilvater.NewMetrics(verifier)
	srv := &kilvater.Server{
		Verifier: verifier,
		Decoy:    http.FileServer(http.Dir(*decoyDir)),
		Logger:   log.Default(),

		AllowPrivate: *allowPrivate,
		Pad:          kilvater.ParsePadMode(*padMode),

		Metrics:          metrics,
		MaxBytesPerKey:   *maxBytesPerKey,
		MaxStreamsPerKey: *maxStreamsPerKey,
	}
	log.Printf("downstream padding: %s", srv.Pad)
	if *maxBytesPerKey > 0 || *maxStreamsPerKey > 0 {
		log.Printf("per-key limits: max_bytes=%d max_streams=%d", *maxBytesPerKey, *maxStreamsPerKey)
	}
	if *metricsAddr != "" {
		startMetrics(*metricsAddr, metrics)
	}

	// SIGHUP re-reads the key files and swaps them in without a restart, so a
	// revocation takes effect for the next authentication and never cuts an
	// open tunnel.
	installReload(srv.Verifier, func() (kilvater.VerifierConfig, error) {
		return loadVerifierConfig(*keysFile, *masterFile, *revokedFile)
	})

	httpSrv := &http.Server{
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ConnState:         metrics.ConnState,
	}
	h2s := &http2.Server{IdleTimeout: 120 * time.Second}

	if *h2cMode {
		// A TLS-terminating proxy stands in front and reaches us over cleartext
		// HTTP/2. The proxy terminates TLS, so its OpenSSL ServerHello is what an
		// observer sees, not Go's, and the certificate lives on the proxy, so a
		// renewal never restarts us and never cuts a session. The HTTP/2 is still
		// ours (the proxy forwards the stream), so we shape its SETTINGS to a
		// stock nginx's (h2server.go) rather than leave Go's showing under the
		// proxy's OpenSSL. We must not be reachable from the outside here:
		// -listen is a unix socket or a loopback address.
		warnIfExposed(*listen)
		ln, err := listenPlain(*listen)
		if err != nil {
			log.Fatal(err)
		}
		ln = shapeServerSettings(ln)
		httpSrv.Handler = h2c.NewHandler(srv, nginxH2Server(120*time.Second))
		log.Printf("kilvaterd listening on %s (cleartext h2c, behind a TLS proxy)", *listen)
		log.Fatal(httpSrv.Serve(ln))
	}

	tlsCfg, err := tlsConfig(*acmeDomain, *acmeCache, *certFile, *keyFile)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}
	ln, err := listenTLS(*listen, tlsCfg, metrics.HandshakeFailed)
	if err != nil {
		log.Fatal(err)
	}
	if err := http2.ConfigureServer(httpSrv, h2s); err != nil {
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

// loadVerifierConfig reads the key material from its files, the way the server
// does at start and again on SIGHUP. A missing keys file is not an error when a
// master is set (a v2-only server keeps no key file); it is an error if neither
// keys nor a master would let anyone authenticate.
func loadVerifierConfig(keysFile, masterFile, revokedFile string) (kilvater.VerifierConfig, error) {
	var cfg kilvater.VerifierConfig
	keys, err := readKeysOptional(keysFile)
	if err != nil {
		return cfg, err
	}
	cfg.Keys = keys
	if masterFile != "" {
		m, err := readMaster(masterFile)
		if err != nil {
			return cfg, fmt.Errorf("master: %w", err)
		}
		cfg.Master = &m
	}
	if revokedFile != "" {
		rev, err := readRevoked(revokedFile)
		if err != nil {
			return cfg, fmt.Errorf("revoked: %w", err)
		}
		cfg.Revoked = rev
	}
	if len(cfg.Keys) == 0 && cfg.Master == nil {
		return cfg, fmt.Errorf("no keys in %s and no master: nothing can authenticate", keysFile)
	}
	return cfg, nil
}

// readKeysOptional reads 64-hex client keys, one per line, '#' comments
// allowed. A file that does not exist yields no keys and no error.
func readKeysOptional(path string) ([]kilvater.Key, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
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
	return keys, nil
}

// readMaster reads a single 64-hex master key.
func readMaster(path string) (kilvater.Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return kilvater.Key{}, err
	}
	return kilvater.ParseKey(strings.TrimSpace(string(data)))
}

// readRevoked reads revoked key ids, one 16-hex line each, '#' comments.
func readRevoked(path string) ([]kilvater.KeyID, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []kilvater.KeyID
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		id, err := kilvater.ParseKeyID(line)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// startMetrics serves the Prometheus metrics endpoint on addr in the
// background. The endpoint names key ids and counts traffic, so it must not be
// reachable from the internet: bind it to the loopback, and let the monitor
// reach it over the existing management channel (SSH or the overlay). A
// non-loopback bind only warns — an operator may front it with their own ACL.
func startMetrics(addr string, m *kilvater.Metrics) {
	host, _, err := net.SplitHostPort(addr)
	ip, perr := netip.ParseAddr(host)
	if err != nil || perr != nil || !ip.IsLoopback() {
		log.Printf("warning: -metrics %q is not a plain loopback address; the metrics endpoint names key ids and counts traffic — keep it unreachable from outside the host", addr)
	}
	ms := &http.Server{Addr: addr, Handler: m, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Printf("kilvaterd metrics on %s/metrics", addr)
		if err := ms.ListenAndServe(); err != nil {
			log.Printf("metrics server: %v", err)
		}
	}()
}

// installReload swaps new key material into the verifier on each SIGHUP. A
// read that fails leaves the current material in place (a bad edit never
// locks everyone out); it never touches open tunnels.
func installReload(v *kilvater.Verifier, load func() (kilvater.VerifierConfig, error)) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		for range ch {
			cfg, err := load()
			if err != nil {
				log.Printf("reload: %v (keeping current keys)", err)
				continue
			}
			v.Reload(cfg)
			log.Printf("reloaded: %d v1 key(s), master=%v, %d revoked", len(cfg.Keys), cfg.Master != nil, len(cfg.Revoked))
		}
	}()
}
