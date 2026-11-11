// Command farvater-fv is the Android-embed entry of farvater-core: a local
// SOCKS5 proxy (username/password, RFC 1929) that routes every connection by
// proven delivery across the paths of a catalogue — kilvater and vkturn among
// them, which sing-box cannot speak. The host app (Vlessa) runs this binary in
// its own :fv process and reads the catalogue text itself (DNS works in the
// JVM), handing it here as a file.
//
// Vlessa routes its own app through the tunnel, so a path's socket would loop
// back into the tunnel unless it is protect()ed. This process cannot call
// VpnService.protect itself, so for every socket the core opens it sends the
// descriptor over the -protect abstract unix socket to the VPN process, which
// protects it and acks. That reuses the exact fd-over-IPC bridge olcRTC uses.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tsyrenov1987/farvater-core/brain"
	"github.com/tsyrenov1987/farvater-core/catalogue"
	"github.com/tsyrenov1987/farvater-core/switchboard"
	"github.com/tsyrenov1987/farvater-core/wire"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	src := flag.String("catalogue", "", "catalogue file (text the app already fetched)")
	user := flag.String("user", "", "SOCKS5 username (RFC 1929); empty = no auth")
	pass := flag.String("pass", "", "SOCKS5 password")
	ctxName := flag.String("ctx", "default", "network context name for receipts")
	protect := flag.String("protect", "", "abstract unix socket the host listens on to protect() each path fd (empty = off)")
	admin := flag.String("admin", "", "admin JSON address (empty = off)")
	verbose := flag.Bool("v", false, "log every receipt")
	flag.Parse()

	logger := log.New(os.Stderr, "", log.LstdFlags)

	if *protect != "" {
		p, err := newProtector(*protect)
		if err != nil {
			logger.Fatalf("protect dial %q: %v", *protect, err)
		}
		wire.SocketControl = p.control
	}

	if *src == "" {
		logger.Fatal("-catalogue is required")
	}
	cat, err := catalogue.Load(*src)
	if err != nil {
		logger.Fatal("catalogue: ", err)
	}

	cfg := switchboard.DefaultConfig()
	cfg.Listen = *listen
	cfg.Ctx = *ctxName
	cfg.User, cfg.Pass = *user, *pass
	cfg.Brain = brain.DefaultConfig()
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
	logger.Printf("farvater-fv %s: %d paths, ctx=%s, auth=%v, protect=%v",
		switchboard.Version, len(sb.Paths()), *ctxName, *user != "", *protect != "")

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

// protector hands each path socket to the VPN process for VpnService.protect
// over a persistent abstract-namespace unix connection, one fd per SCM_RIGHTS
// message, and waits for a one-byte ack. It fails closed: if the bridge is down
// the dial fails and the path is marked bad, which is safe — better a dropped
// path than one that loops into the tunnel.
type protector struct {
	addr *net.UnixAddr
	mu   sync.Mutex
	conn *net.UnixConn
}

func newProtector(name string) (*protector, error) {
	p := &protector{addr: &net.UnixAddr{Name: abstractName(name), Net: "unix"}}
	if err := p.reconnect(); err != nil {
		return nil, err
	}
	return p, nil
}

// abstractName maps "@foo" or a bare "foo" to the Linux abstract socket
// "\x00foo" (what Android's LocalServerSocket reserves); a name with a slash is
// left as a filesystem path.
func abstractName(n string) string {
	switch {
	case strings.HasPrefix(n, "@"):
		return "\x00" + n[1:]
	case strings.HasPrefix(n, "\x00"), strings.Contains(n, "/"):
		return n
	default:
		return "\x00" + n
	}
}

func (p *protector) reconnect() error {
	c, err := net.DialUnix("unix", nil, p.addr)
	if err != nil {
		return err
	}
	p.conn = c
	return nil
}

func (p *protector) control(network, address string, c syscall.RawConn) error {
	var opErr error
	if err := c.Control(func(fd uintptr) { opErr = p.protect(int(fd)) }); err != nil {
		return err
	}
	return opErr
}

func (p *protector) protect(fd int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn == nil {
		if err := p.reconnect(); err != nil {
			return err
		}
	}
	_ = p.conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := p.conn.WriteMsgUnix([]byte{1}, syscall.UnixRights(fd), nil); err != nil {
		p.drop()
		return err
	}
	ack := make([]byte, 1)
	if _, err := p.conn.Read(ack); err != nil {
		p.drop()
		return err
	}
	if ack[0] != 1 {
		return errors.New("host refused to protect socket")
	}
	return nil
}

func (p *protector) drop() {
	if p.conn != nil {
		_ = p.conn.Close()
		p.conn = nil
	}
}
