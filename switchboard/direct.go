package switchboard

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

// DirectNames reads the sites a person wants around the tunnel, one or many
// per line, separated by spaces, commas or semicolons, as typed or pasted:
// "https://online.sberbank.ru/x", "*.tbank.ru", "Сбербанк.рф" and "1.2.3.4"
// become "online.sberbank.ru", "tbank.ru", "xn--80abap1arsf.xn--p1ai" and
// "1.2.3.4". Anything that is neither a domain name nor an IP address is left
// out; each name is kept once, in the order given. Never nil.
func DirectNames(input string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(input, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		if n := directName(f); n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

func directName(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.Trim(strings.TrimPrefix(s, "["), "]")
	if ip, err := netip.ParseAddr(s); err == nil {
		return ip.Unmap().String()
	}
	s = strings.Trim(strings.TrimPrefix(s, "*."), ".")
	n, err := idna.Lookup.ToASCII(s)
	if err != nil || !strings.Contains(n, ".") {
		return ""
	}
	return n
}

// isDirect reports whether host is one of Config.Direct or a subdomain of one.
func (s *Switchboard) isDirect(host string) bool {
	if len(s.cfg.Direct) == 0 {
		return false
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.Unmap().String()
	}
	for _, d := range s.cfg.Direct {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// serveDirect connects the app to its destination over the device's own
// network, around every path: the core's sockets stay out of the device
// tunnel (iOS keeps a packet tunnel's own traffic out of it, Android excludes
// the app), so the site sees the device's own address. No receipt is written:
// such a flow says nothing about any path.
func (s *Switchboard) serveDirect(ctx context.Context, c net.Conn, req socksRequest) {
	defer c.Close()
	d := net.Dialer{Timeout: s.cfg.DialTimeout}
	r, err := d.DialContext(ctx, "tcp", req.String())
	if err != nil {
		s.logf("direct %s: %v", req, err)
		_ = replySocks5(c, 4) // host unreachable
		return
	}
	defer r.Close()
	if err := replySocks5(c, 0); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	s.direct.Add(1)
	stop := context.AfterFunc(ctx, func() { c.Close(); r.Close() })
	defer stop()
	go func() {
		// The app finished sending: pass that on and keep reading the answer.
		_, _ = io.Copy(r, c)
		if tc, ok := r.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	// The site finished: the deferred closes end the other direction too.
	_, _ = io.Copy(c, r)
}
