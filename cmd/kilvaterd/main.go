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
	"strconv"
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
	masterFile := flag.String("master", "", "master key file enabling v2 derived keys: one 64-hex master per line, '#' comments, each accepted (a node's own master from -nodemaster, and the fleet master while clients move over); empty disables v2")
	revokedFile := flag.String("revoked", "", "revoked v2 key ids, one 16-hex line each, '#' comments (reloaded on SIGHUP)")
	allowedFile := flag.String("allowed", "", "the only v2 key ids accepted, one 16-hex line each, '#' comments (reloaded on SIGHUP); while the file does not exist every id a master derives is accepted")
	decoyDir := flag.String("decoy", "/var/www/html", "static files served to non-tunnel visitors")
	acmeDomain := flag.String("acme", "", "domain to get a Let's Encrypt certificate for (TLS-ALPN-01); empty uses -cert/-key")
	acmeCache := flag.String("acme-cache", "/var/lib/kilvaterd/acme", "directory where autocert stores certificates")
	allowPrivate := flag.Bool("allow-private", false, "let clients reach loopback, private and link-local addresses (off: only public addresses)")
	padMode := flag.String("pad", "moderate", "downstream traffic padding: off | moderate | heavy | site (site: behind nginx, bulk leaves in the record lengths of nginx's own file downloads)")
	h2cMode := flag.Bool("h2c", false, "serve cleartext HTTP/2 for a TLS-terminating proxy (nginx/Caddy) in front; -listen may be unix:/path, and -cert/-key/-acme are ignored")
	genKey := flag.Bool("genkey", false, "print a new random client key and exit")
	genMaster := flag.Bool("genmaster", false, "print a new random master key and exit")
	issue := flag.String("issue", "", "with -master (the fleet master on the first line): print the key id and derived key for this subscriber id, and exit")
	node := flag.String("node", "", "with -issue: derive the key bound to this node (from its node master), as the worker does; with -nodemaster: the node to bind")
	nodeMaster := flag.Bool("nodemaster", false, "with -master (the fleet master, first line) and -node: print that node's master, for the node's -master file, and exit")
	metricsAddr := flag.String("metrics", "", "serve Prometheus metrics on this address (e.g. 127.0.0.1:9900); empty disables it; keep it on the loopback or a management overlay, never public")
	maxBytesPerKey := flag.Int64("max-bytes-per-key", 0, "refuse a key's new streams once it has carried this many payload bytes up+down; 0 is no limit")
	maxBytesWindow := flag.Duration("max-bytes-window", 0, "with -max-bytes-per-key: count a key's bytes per window of this length (e.g. 24h) instead of for the life of the process; 0 is no window")
	maxStreamsPerKey := flag.Int64("max-streams-per-key", 0, "cap a key's concurrent streams; 0 is no limit")
	denyDst := flag.String("deny-dst", "", "comma-separated addresses or prefixes (the sister nodes) clients may reach only on -self-ports; the server's own addresses are always in the list")
	denyDstFile := flag.String("deny-dst-file", "", "more -deny-dst addresses or prefixes, one per line, '#' comments (reloaded on SIGHUP); a missing file adds nothing")
	selfPorts := flag.String("self-ports", "80,443", "target ports left open on the server's own addresses and on -deny-dst")
	denyPorts := flag.String("deny-ports", "25", "target ports no client may reach, comma-separated; empty allows all")
	resumeGrace := flag.Duration("resume-grace", kilvater.DefaultResumeGrace, "how long a TCP flow whose stream was lost waits for its client to come back on another stream; 0 turns resumable flows off")
	resumeMaxBytes := flag.Int64("resume-max-bytes", kilvater.DefaultResumeMaxBytes, "stop keeping flows that lose their stream while this many bytes are buffered for clients")
	resumeMaxKept := flag.Int64("resume-max-kept", kilvater.DefaultResumeMaxKept, "stop keeping flows that lose their stream while this many already wait for their client")
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
	if *nodeMaster {
		if *masterFile == "" || *node == "" {
			log.Fatal("-nodemaster needs -master and -node")
		}
		masters, err := readMasters(*masterFile)
		if err != nil {
			log.Fatalf("master: %v", err)
		}
		nm := kilvater.NodeMaster(masters[0], *node)
		fmt.Println(hex.EncodeToString(nm[:]))
		return
	}
	if *issue != "" {
		if *masterFile == "" {
			log.Fatal("-issue needs -master")
		}
		masters, err := readMasters(*masterFile)
		if err != nil {
			log.Fatalf("master: %v", err)
		}
		master := masters[0]
		id := kilvater.KeyIDFor(master, []byte(*issue))
		if *node != "" {
			master = kilvater.NodeMaster(master, *node)
		}
		k := kilvater.DeriveKey(master, id)
		// k[:] prints the real key bytes; %x on a Key would hit its redacting
		// String, which is exactly what we must bypass here to hand out the key.
		fmt.Printf("kid=%s key=%s\n", id, hex.EncodeToString(k[:]))
		return
	}

	cfg, err := loadVerifierConfig(*keysFile, *masterFile, *revokedFile, *allowedFile)
	if err != nil {
		log.Fatalf("keys: %v", err)
	}
	log.Printf("loaded %d v1 key(s), %d master(s), %d revoked, %s", len(cfg.Keys), nMasters(cfg), len(cfg.Revoked), allowNote(cfg))

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
		MaxBytesWindow:   *maxBytesWindow,

		ResumeGrace:    *resumeGrace,
		ResumeMaxBytes: *resumeMaxBytes,
		ResumeMaxKept:  *resumeMaxKept,
	}
	metrics.Resume = srv.ResumeStats
	if srv.DenyDst, err = denyPrefixes(*denyDst); err != nil {
		log.Fatalf("-deny-dst: %v", err)
	}
	if *denyDstFile != "" {
		loadDeny := func() {
			list, err := readPrefixFile(*denyDstFile)
			if err != nil {
				log.Printf("-deny-dst-file: %v (keeping the current list)", err)
				return
			}
			srv.SetDenyExtra(list)
			log.Printf("deny-dst-file: %d prefix(es)", len(list))
		}
		loadDeny()
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGHUP)
		go func() {
			for range ch {
				loadDeny()
			}
		}()
	}
	if srv.SelfPorts, err = parsePorts(*selfPorts); err != nil {
		log.Fatalf("-self-ports: %v", err)
	}
	if srv.DenyPorts, err = parsePorts(*denyPorts); err != nil {
		log.Fatalf("-deny-ports: %v", err)
	}
	log.Printf("targets: %d own/sister prefix(es) open on ports %v only, ports %v closed", len(srv.DenyDst), srv.SelfPorts, srv.DenyPorts)
	log.Printf("downstream padding: %s", srv.Pad)
	if *maxBytesPerKey > 0 || *maxStreamsPerKey > 0 {
		log.Printf("per-key limits: max_bytes=%d per %v, max_streams=%d", *maxBytesPerKey, *maxBytesWindow, *maxStreamsPerKey)
	}
	if *metricsAddr != "" {
		startMetrics(*metricsAddr, metrics)
	}

	// SIGHUP re-reads the key files and swaps them in without a restart, so a
	// revocation takes effect for the next authentication and never cuts an
	// open tunnel.
	installReload(srv.Verifier, func() (kilvater.VerifierConfig, error) {
		return loadVerifierConfig(*keysFile, *masterFile, *revokedFile, *allowedFile)
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
		// net/http never reports a hijacked (h2c) connection closed, so count
		// connections at the listener instead of through ConnState.
		httpSrv.ConnState = nil
		ln = shapeServerSettings(countConns(ln, metrics))
		// On this path TLS (the front proxy's OpenSSL) and the HTTP/2 above are
		// nginx's, so the decoy's HTTP responses must be nginx's too, not Go's
		// FileServer (decoy.go). The direct-TLS path below keeps the plain Go
		// handler, where the whole stack is Go.
		srv.Decoy = newNginxDecoy(srv.Decoy)
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
func loadVerifierConfig(keysFile, masterFile, revokedFile, allowedFile string) (kilvater.VerifierConfig, error) {
	var cfg kilvater.VerifierConfig
	keys, err := readKeysOptional(keysFile)
	if err != nil {
		return cfg, err
	}
	cfg.Keys = keys
	if masterFile != "" {
		ms, err := readMasters(masterFile)
		if err != nil {
			return cfg, fmt.Errorf("master: %w", err)
		}
		cfg.Master = &ms[0]
		cfg.Masters = ms[1:]
	}
	if revokedFile != "" {
		rev, err := readRevoked(revokedFile)
		if err != nil {
			return cfg, fmt.Errorf("revoked: %w", err)
		}
		cfg.Revoked = rev
	}
	if allowedFile != "" {
		// The list is a file another program keeps (the node agent, from the
		// roster). Until it has written one there is no list, not an empty one:
		// an empty list would lock every subscriber out.
		if _, err := os.Stat(allowedFile); err == nil {
			ids, err := readRevoked(allowedFile)
			if err != nil {
				return cfg, fmt.Errorf("allowed: %w", err)
			}
			cfg.Allowed, cfg.AllowList = ids, true
		} else if !errors.Is(err, os.ErrNotExist) {
			return cfg, fmt.Errorf("allowed: %w", err)
		}
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

// nMasters counts the masters a config accepts v2 keys under, for the log.
func nMasters(cfg kilvater.VerifierConfig) int {
	if cfg.Master == nil {
		return 0
	}
	return 1 + len(cfg.Masters)
}

// readMasters reads master keys, one 64-hex line each, '#' comments allowed;
// at least one. A one-line file (the old format) reads as before.
func readMasters(path string) ([]kilvater.Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ms []kilvater.Key
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		k, err := kilvater.ParseKey(line)
		if err != nil {
			return nil, err
		}
		ms = append(ms, k)
	}
	if len(ms) == 0 {
		return nil, errors.New("no master key in file")
	}
	return ms, nil
}

func allowNote(cfg kilvater.VerifierConfig) string {
	if !cfg.AllowList {
		return "no allow list"
	}
	return fmt.Sprintf("%d allowed", len(cfg.Allowed))
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
			log.Printf("reloaded: %d v1 key(s), %d master(s), %d revoked, %s", len(cfg.Keys), nMasters(cfg), len(cfg.Revoked), allowNote(cfg))
		}
	}()
}

// parsePrefix reads one address or prefix.
func parsePrefix(f string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(f); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(f)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is neither an address nor a prefix", f)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// readPrefixFile reads the -deny-dst-file list. A file that does not exist
// yields an empty list; one bad line fails the whole read, so a broken edit
// never loosens the list in force.
func readPrefixFile(path string) ([]netip.Prefix, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		p, err := parsePrefix(line)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// denyPrefixes is the -deny-dst list plus every address on the host's own
// interfaces (loopback and private ones are refused elsewhere; listing them
// again is harmless).
func denyPrefixes(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(list, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("%q is neither an address nor a prefix", f)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, ia := range addrs {
		ipn, ok := ia.(*net.IPNet)
		if !ok {
			continue
		}
		if a, ok := netip.AddrFromSlice(ipn.IP); ok {
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out, nil
}

func parsePorts(list string) ([]uint16, error) {
	var out []uint16
	for _, f := range strings.Split(list, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, err := strconv.ParseUint(f, 10, 16)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("bad port %q", f)
		}
		out = append(out, uint16(n))
	}
	return out, nil
}
