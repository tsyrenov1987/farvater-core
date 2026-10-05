// Command farvater is the reference CLI of farvater-core: a local SOCKS5
// proxy that routes every connection by proven delivery across the paths of a
// catalogue, plus a few inspection commands.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"

	"github.com/tsyrenov1987/farvater-core/brain"
	"github.com/tsyrenov1987/farvater-core/catalogue"
	"github.com/tsyrenov1987/farvater-core/switchboard"
)

func usage() {
	fmt.Fprintf(os.Stderr, `farvater %s — delivery-proof path selection

usage:
  farvater run    -catalogue <url|file> [-listen 127.0.0.1:1080] [-admin 127.0.0.1:1081] [-ctx name] [-v]
  farvater probe  -catalogue <url|file> [-url https://...] [-timeout 15s]
  farvater paths  -catalogue <url|file>
  farvater status [-admin 127.0.0.1:1081]
  farvater journal [-admin 127.0.0.1:1081]
  farvater receipts [-admin 127.0.0.1:1081]
`, switchboard.Version)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "run":
		cmdRun(os.Args[2:])
	case "probe":
		cmdProbe(os.Args[2:])
	case "paths":
		cmdPaths(os.Args[2:])
	case "status", "journal", "receipts":
		cmdAdmin(os.Args[1], os.Args[2:])
	case "version":
		fmt.Println(switchboard.Version)
	default:
		usage()
	}
}

func loadCatalogue(src string) *catalogue.Catalogue {
	if src == "" {
		fmt.Fprintln(os.Stderr, "-catalogue is required")
		os.Exit(2)
	}
	cat, err := catalogue.Load(src)
	if err != nil {
		fmt.Fprintln(os.Stderr, "catalogue:", err)
		os.Exit(1)
	}
	return cat
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	src := fs.String("catalogue", "", "catalogue URL or file")
	listen := fs.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	admin := fs.String("admin", "127.0.0.1:1081", "admin JSON address (empty = off)")
	ctxName := fs.String("ctx", "default", "network context name for receipts")
	verbose := fs.Bool("v", false, "log every receipt")
	_ = fs.Parse(args)

	cat := loadCatalogue(*src)
	cfg := switchboard.DefaultConfig()
	cfg.Listen = *listen
	cfg.Ctx = *ctxName
	cfg.Brain = brain.DefaultConfig()
	logger := log.New(os.Stderr, "", log.LstdFlags)
	if *verbose {
		cfg.Log = logger.Printf
	}
	sb, err := switchboard.New(cfg, cat)
	if err != nil {
		logger.Fatal(err)
	}
	for _, sk := range sb.Skipped {
		logger.Printf("skipped path %s", sk)
	}
	logger.Printf("farvater %s: %d paths from %q", switchboard.Version, len(sb.Paths()), cat.Title)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *admin != "" {
		go func() {
			if err := sb.ServeAdmin(ctx, *admin); err != nil {
				logger.Printf("admin: %v", err)
			}
		}()
	}
	if err := sb.Serve(ctx); err != nil {
		logger.Fatal(err)
	}
}

func cmdPaths(args []string) {
	fs := flag.NewFlagSet("paths", flag.ExitOnError)
	src := fs.String("catalogue", "", "catalogue URL or file")
	_ = fs.Parse(args)
	cat := loadCatalogue(*src)
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tRAIL\tSERVER\tFLOW\tSNI")
	for _, e := range cat.Paths {
		fmt.Fprintf(tw, "%s\t%s\t%s:%d\t%s\t%s\n", e.ID, e.Spec.Rail(), e.Spec.Host, e.Spec.Port, e.Spec.Flow, e.Spec.ServerSNI())
	}
	tw.Flush()
}

func cmdAdmin(what string, args []string) {
	fs := flag.NewFlagSet(what, flag.ExitOnError)
	admin := fs.String("admin", "127.0.0.1:1081", "admin JSON address")
	raw := fs.Bool("json", false, "print raw JSON")
	_ = fs.Parse(args)
	resp, err := http.Get("http://" + *admin + "/" + what)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if *raw || what != "status" {
		os.Stdout.Write(body)
		return
	}
	var st switchboard.Status
	if err := json.Unmarshal(body, &st); err != nil {
		os.Stdout.Write(body)
		return
	}
	fmt.Printf("farvater %s  up %ds  ctx=%s  flows=%d active=%d retries=%d dropped=%d  leader=%s\n",
		st.Version, st.UptimeSec, st.Ctx, st.Flows, st.Active, st.Retries, st.Dropped, st.Leader)
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "PATH\tRAIL\tDELIV\tFIRSTBYTE\tN\t15M\tP90FB\tFLAGS")
	for _, p := range st.Paths {
		flags := ""
		if p.Leader {
			flags += "leader "
		}
		if p.Cut16 {
			flags += "cut16 "
		}
		if p.Parked {
			flags += "parked "
		}
		fmt.Fprintf(tw, "%s\t%s\t%.2f\t%.2f\t%d\t%d\t%d\t%s\n", p.ID, p.Rail, p.DelivMean, p.FbMean, p.Receipts, p.Recent15m, p.P90FirstByteMs, flags)
	}
	tw.Flush()
	for _, sk := range st.Skipped {
		fmt.Println("skipped:", sk)
	}
}
