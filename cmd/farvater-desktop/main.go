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
			answer = desktop.Explain(err)
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
	cfg.RuDirect, cfg.DirectName = true, desktop.DirectName
	cfg.RuDialTimeout, cfg.RuRetryAfter = desktop.RuDialTimeout, desktop.RuRetryAfter
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
	sys, err := desktop.Up(desktop.Options{Nodes: desktop.NodeAddrs(cat), KillSwitch: kill, Logf: logger.Printf})
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
