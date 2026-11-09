// Command farvater-desktop is Farvater for macOS and Windows: the whole
// machine goes through the catalogue's paths (the computer catalogue: foreign
// servers only, reached directly), Russian sites go straight to the network
// as on the phones. Run it as root (macOS) or Administrator (Windows).
//
//	farvater-desktop connect ORDEN-XXXXX-XXXXX   (or a catalogue URL)
//	farvater-desktop off                         (undo a run that did not clean up)
//
// On Windows a run with no arguments (a double click) asks for Administrator
// and for the access code.
package main

import (
	"context"
	"crypto/rand"
	"errors"
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
	"time"

	"github.com/tsyrenov1987/farvater-core/catalogue"
	"github.com/tsyrenov1987/farvater-core/desktop"
	"github.com/tsyrenov1987/farvater-core/switchboard"
)

var codeRE = regexp.MustCompile(`^ORDEN-[0-9A-Z]{5}-[0-9A-Z]{5}$`)

const probeURL = "https://www.gstatic.com/generate_204"

// A Russian site's direct dial, name lookup included (3 s was too short: on a
// healthy Windows machine www.vtb.ru failed 2 dials of 3 with it, and none
// with 10 s), and how soon a site that failed it is tried directly again.
const (
	ruDialTimeout = 10 * time.Second
	ruRetryAfter  = 30 * time.Second
)

func usage() {
	fmt.Fprintf(os.Stderr, "farvater-desktop %s\n\nusage:\n  farvater-desktop connect <ORDEN-code | catalogue URL> [-v] [-no-killswitch]\n  farvater-desktop off\n", switchboard.Version)
	os.Exit(2)
}

// catalogueHosts serve the same /hsub catalogue. joinorden.com is cut off
// inside Russia (TLS reset), the other two are reachable from there and from abroad.
var catalogueHosts = []string{"viporden.online", "myorden.ru", "joinorden.com"}

// catalogueURLs turns an access code into the catalogue's addresses, in the
// order to try them; a URL the user gave is the only address.
func catalogueURLs(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if u := strings.ToUpper(s); codeRE.MatchString(u) {
		var out []string
		for _, h := range catalogueHosts {
			out = append(out, "https://"+h+"/hsub/"+u)
		}
		return out, nil
	}
	if strings.HasPrefix(s, "https://") {
		return []string{s}, nil
	}
	return nil, fmt.Errorf("not an access code or https URL: %q", s)
}

// A window opened by a double click sets these: it closes the moment the
// program ends, and nobody has read the logs in it.
var (
	pauseOnError  = func() {}
	connectedNote string
)

func main() {
	logger := log.New(os.Stderr, "", log.LstdFlags)
	if len(os.Args) < 2 {
		args := startByDoubleClick()
		if args == nil {
			usage()
		}
		connectAndExit(args, logger)
		return
	}
	switch os.Args[1] {
	case "off":
		if err := desktop.Off(); err != nil && !os.IsNotExist(err) {
			logger.Fatal(err)
		}
		fmt.Println("off")
	case "connect":
		connectAndExit(os.Args[2:], logger)
	case "version":
		fmt.Println(switchboard.Version)
	default:
		usage()
	}
}

func connectAndExit(args []string, logger *log.Logger) {
	release := holdConsole()
	err := connect(args, logger)
	release()
	if err != nil {
		logger.Print(err)
		pauseOnError()
		os.Exit(1)
	}
}

// explain turns the worker's answers about a code (/hsub in orden-worker) into
// what the code's owner can act on; nil means the error says nothing about the
// code, a network failure for one.
func explain(err error) error {
	const cabinet = " Кабинет: myorden.ru/cabinet"
	switch {
	case errors.Is(err, catalogue.ErrNoPaths):
		return errors.New("Для этого кода сервер не выдал подключений: компьютер работает в пробный период и на тарифах «Телефон + компьютер» и «+Компьютер»." + cabinet)
	case strings.Contains(err.Error(), "HTTP 404"):
		return errors.New("Такого кода нет или он отключён. Проверьте код." + cabinet)
	case strings.Contains(err.Error(), "HTTP 403"):
		return errors.New("Тариф по этому коду закончился или исчерпан лимит трафика." + cabinet)
	case strings.Contains(err.Error(), "HTTP 409"):
		return errors.New("На этом коде заняты все устройства." + cabinet)
	}
	return nil
}

func connect(args []string, logger *log.Logger) error {
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
	urls, err := catalogueURLs(src)
	if err != nil {
		return err
	}
	if !isAdmin() {
		return errors.New("run as root (sudo) on macOS or as Administrator on Windows")
	}
	logger.Printf("farvater-desktop %s: loading the server list", switchboard.Version)
	// The catalogue comes before the tunnel: the computer catalogue (the
	// worker knows it by the core's User-Agent, "farvater-core/... (darwin)").
	var cat *catalogue.Catalogue
	var answer error // the first thing a host said about the code: the last host may be cut off
	for _, u := range urls {
		if cat, err = catalogue.Load(u); err == nil {
			break
		}
		if verbose {
			logger.Printf("catalogue %s: %v", u, err)
		}
		if answer == nil {
			answer = explain(err)
		}
	}
	if err != nil {
		if answer != nil {
			return answer
		}
		return fmt.Errorf("catalogue: %w", err)
	}
	cfg := switchboard.DefaultConfig()
	cfg.User, cfg.Pass = rand.Text(), rand.Text()
	cfg.RuDirect = true
	cfg.RuDialTimeout, cfg.RuRetryAfter = ruDialTimeout, ruRetryAfter
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
		return err
	}
	logger.Printf("farvater-desktop %s: %d paths", switchboard.Version, len(sb.Paths()))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	sys, err := desktop.Up(desktop.Options{Nodes: nodeAddrs(cat), KillSwitch: kill, Logf: logger.Printf})
	if err != nil {
		return err
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
		return err
	}
	logger.Print("connected; Ctrl+C to disconnect")
	if connectedNote != "" {
		fmt.Println(connectedNote)
	}
	<-ctx.Done()
	_ = sb.SaveMemory()
	logger.Print("disconnected")
	return nil
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
