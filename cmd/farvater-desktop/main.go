// Command farvater-desktop is Farvater for macOS and Windows: the whole
// machine goes through the catalogue's paths (the computer catalogue: foreign
// servers only, reached directly), Russian sites go straight to the network
// as on the phones. Run it as root (macOS) or Administrator (Windows).
//
//	farvater-desktop connect ORDEN-XXXXX-XXXXX   (or a catalogue URL)
//	farvater-desktop off                         (undo a run that did not clean up)
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/tsyrenov1987/farvater-core/catalogue"
	"github.com/tsyrenov1987/farvater-core/desktop"
	"github.com/tsyrenov1987/farvater-core/switchboard"
)

var codeRE = regexp.MustCompile(`^ORDEN-[0-9A-Z]{5}-[0-9A-Z]{5}$`)

const probeURL = "https://www.gstatic.com/generate_204"

func usage() {
	fmt.Fprintf(os.Stderr, "farvater-desktop %s\n\nusage:\n  farvater-desktop connect <ORDEN-code | catalogue URL> [-v] [-no-killswitch]\n  farvater-desktop off\n", switchboard.Version)
	os.Exit(2)
}

// catalogueURL turns an access code into the catalogue's address.
func catalogueURL(s string) (string, error) {
	s = strings.TrimSpace(s)
	if u := strings.ToUpper(s); codeRE.MatchString(u) {
		return "https://joinorden.com/hsub/" + u, nil
	}
	if strings.HasPrefix(s, "https://") {
		return s, nil
	}
	return "", fmt.Errorf("not an access code or https URL: %q", s)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	logger := log.New(os.Stderr, "", log.LstdFlags)
	switch os.Args[1] {
	case "off":
		if err := desktop.Off(); err != nil && !os.IsNotExist(err) {
			logger.Fatal(err)
		}
		fmt.Println("off")
	case "connect":
		connect(os.Args[2:], logger)
	case "version":
		fmt.Println(switchboard.Version)
	default:
		usage()
	}
}

func connect(args []string, logger *log.Logger) {
	var src string
	verbose, kill := false, true
	for _, a := range args {
		switch a {
		case "-v":
			verbose = true
		case "-no-killswitch":
			kill = false
		default:
			src = a
		}
	}
	u, err := catalogueURL(src)
	if err != nil {
		logger.Fatal(err)
	}
	if !isAdmin() {
		logger.Fatal("run as root (sudo) on macOS or as Administrator on Windows")
	}
	// The catalogue comes before the tunnel: the computer catalogue (the
	// worker knows it by the core's User-Agent, "farvater-core/... (darwin)").
	cat, err := catalogue.Load(u)
	if err != nil {
		logger.Fatal("catalogue: ", err)
	}
	cfg := switchboard.DefaultConfig()
	cfg.User, cfg.Pass = rand.Text(), rand.Text()
	cfg.RuDirect = true
	cfg.ProbeURL = probeURL
	if len(cat.ProbeURLs) > 0 {
		cfg.ProbeURL = cat.ProbeURLs[0]
	}
	cfg.MemoryFile = filepath.Join(desktop.StateDir, "memory.json")
	if verbose {
		cfg.Log = logger.Printf
	}
	sb, err := switchboard.New(cfg, cat)
	if err != nil {
		logger.Fatal(err)
	}
	logger.Printf("farvater-desktop %s: %d paths", switchboard.Version, len(sb.Paths()))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	sys, err := desktop.Up(desktop.Options{Nodes: nodeAddrs(cat), KillSwitch: kill, Logf: logger.Printf})
	if err != nil {
		logger.Fatal(err)
	}
	defer sys.Down()
	defer func() {
		if r := recover(); r != nil {
			sys.Down()
			panic(r)
		}
	}()
	sb.Attach(ctx)
	if _, err := desktop.Start(ctx, sys, sb.ServeConn, cfg.User, cfg.Pass, logger.Printf); err != nil {
		logger.Print(err)
		return
	}
	logger.Print("connected; Ctrl+C to disconnect")
	<-ctx.Done()
	_ = sb.SaveMemory()
	logger.Print("disconnected")
}

// nodeAddrs lists the catalogue's server addresses, names resolved now,
// before the tunnel takes the system's DNS.
func nodeAddrs(cat *catalogue.Catalogue) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	add := func(a netip.Addr) {
		if a = a.Unmap(); a.IsValid() && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, e := range cat.Paths {
		if a, err := netip.ParseAddr(e.Spec.Host); err == nil {
			add(a)
			continue
		}
		if as, err := net.LookupHost(e.Spec.Host); err == nil {
			for _, s := range as {
				if a, err := netip.ParseAddr(s); err == nil {
					add(a)
				}
			}
		}
	}
	return out
}
