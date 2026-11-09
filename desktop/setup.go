package desktop

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/tsyrenov1987/farvater-core/catalogue"
)

// A Russian site's direct dial, name lookup included (3 s was too short: on a
// healthy Windows machine www.vtb.ru failed 2 dials of 3 with it, and none
// with 10 s), and how soon a site that failed it is tried directly again.
const (
	RuDialTimeout = 10 * time.Second
	RuRetryAfter  = 30 * time.Second
)

// Explain turns the worker's answers about a code (/hsub in orden-worker) into
// what the code's owner can act on; nil means the error says nothing about the
// code, a network failure for one.
func Explain(err error) error {
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

// NodeAddrs lists the catalogue's server addresses, names resolved now,
// before the tunnel takes the system's DNS.
func NodeAddrs(cat *catalogue.Catalogue) []netip.Addr {
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
