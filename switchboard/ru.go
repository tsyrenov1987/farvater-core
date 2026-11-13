package switchboard

import (
	"context"
	_ "embed"
	"encoding/binary"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/tsyrenov1987/farvater-core/wire"
)

// Russian sites go straight to the network by default (Config.RuDirect): a
// Russian bank, marketplace or messenger that sees a foreign address refuses
// the person, or reports the address as a VPN's. The same set the Orden
// clients send direct: the .ru, .su and .рф zones, the big Russian services
// on other names, the "what is my IP" services such apps ask, and addresses
// registered to Russia (RIPE NCC, go run ./tools/ruip). A name is matched as
// the app gave it (hev hands names, not addresses, for what it resolved);
// the address ranges cover apps that dial an address of their own.

// ruNames are matched with their subdomains.
var ruNames = []string{
	"ru", "su", "xn--p1ai", // .рф
	"vk.com", "yandex.com", "yandex.net", "sberbank.com", "gazprombank.com",
	// "What is my IP" services (MAX asks ifconfig.me, api.ipify.org and
	// checkip.amazonaws.com, Habr 1006666).
	"ifconfig.me", "ifconfig.co", "ipify.org", "checkip.amazonaws.com", "icanhazip.com",
	"ipinfo.io", "ip-api.com", "ipapi.co", "ident.me", "myexternalip.com", "ipecho.net", "2ip.io",
	// The Russian services' own names outside the zones: their CDNs, apps and
	// payment pages (the list support handed out on 09.11 for iOS's direct list).
	// Yandex
	"yastatic.net", "yastat.net", "yandexcloud.net", "yandex.cloud", "yandex.st", "yandex.market",
	"yandex.taxi", "yandexgo.com", "yandex-bank.net", "yadi.sk", "ya.cc", "naydex.net", "yndx.net",
	"clstorage.net", "static-storage.net", "yandexadexchange.net", "yandexmetrica.com",
	"webvisor.com", "webvisor.org", "turbopages.org", "yandexwebcache.net", "yandexwebcache.org",
	"shedevrum.ai", "shedevrum.com",
	// VK and Mail.ru
	"userapi.com", "vkuser.net", "vkuseraudio.net", "vkuseraudio.com", "vkuservideo.net",
	"vkuservideo.com", "vkuserlive.net", "vkuserlive.com", "vk-cdn.net", "cdn-vk.net",
	"vk-portal.net", "vkcdnservice.com", "vk.me", "vk.cc", "vk.link", "mvk.com", "vkontakte.com",
	"vkmessenger.com", "vkmessenger.app", "vkpay.com", "vkpay.app", "vkpay.io", "vk.company",
	"vk.team", "vkgo.app", "vkclips.app", "vklive.app", "vkplay.live", "vkcs.cloud", "vk-apps.com",
	"mycdn.me", "ok.me", "mradx.net", "myadx.net", "smailru.net", "vmailru.net", "bizmrg.com",
	"my.games", "my.com", "mytrk.link", "staticmy.com", "youla.io", "tamtam.chat",
	// Banks and payments
	"tbank-online.com", "tinkoffmobile.com", "tinkoff-group.com", "t.finance", "alfa.me",
	"alfabank.st", "vtb.com", "tochka.com", "home.bank", "koronapay.com", "sber.pro", "sberauto.com",
	"sberbank-tele.com", "spasibo.digital", "spasibo.market", "gazprombank.investments", "giga.chat",
	"best2pay.net", "bank131.com", "rbsgate.com", "moex.com", "renins.com",
	// Shops, marketplaces and delivery
	"ozon.com", "ozon.app", "ozon.tech", "ozon.travel", "ozon.express", "ozon.market",
	"ozonusercontent.com", "wbstatic.net", "wbcontent.net", "paywb.com", "wbwh.tech", "wibes.com",
	"avito.com", "avito.st", "avito.tech", "megamarket.tech", "flowwow.com", "flowwow-images.com",
	"funpay.com", "lenta.com", "magnit.com", "perekrestok.com", "fix-price.com", "5post.market",
	"chizhik.club", "ostin.com", "cdek.shopping", "dodopizza.com", "dodois.com", "dodois.io",
	"dodostatic.net",
	// Video and streaming
	"ivi.tv", "ivicdn.tv", "okko.tv", "okkoapi.tv", "okko.sport", "more.tv", "premier.one", "wink.am",
	"restream-media.net", "smotreshka.tv", "24h.tv", "rutube.sport", "kinescopecdn.net",
	"cdnvideohub.com", "boosty.to", "donationalerts.com", "memealerts.com",
	// Other services
	"2gis.com", "aviasales.com", "gismeteo.com", "gismeteo.net", "gismeteo.st", "meteofor.com",
	"megafon.com", "beeline.tv", "mts-ws.net", "bitrix24.com", "bitrix24.net", "bitrixsoft.com",
	"bitrix.info", "kaspersky.com", "kaspersky-labs.com", "drweb.com", "otzovik.com", "taxsee.com",
	"medsi.com", "gorzdrav.org", "emias.info", "selcdn.net", "ngenix.net", "ktalk.host",
	"kontur.host", "express.ms",
}

// RIPE NCC delegations to RU, merged: ru4 is big-endian uint32 pairs
// [first, last], ru6 big-endian uint64 pairs over an address's top 64 bits.
// Searched in place, so they cost no heap (the iOS tunnel has 28 MB in all).
//
//go:embed ru4.bin
var ru4 string

//go:embed ru6.bin
var ru6 string

// ruDirectFor is how long a site whose direct dial failed goes over the paths
// instead (an allow-listed mobile network drops the sites not on its list,
// which the paths still reach); ruDialTimeout bounds that direct dial.
const (
	ruDirectFor   = 10 * time.Minute
	ruDialTimeout = 3 * time.Second
)

func isRuName(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, n := range ruNames {
		if host == n || strings.HasSuffix(host, "."+n) {
			return true
		}
	}
	return false
}

func isRuIP(a netip.Addr) bool {
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		return inRanges(ru4, 4, uint64(binary.BigEndian.Uint32(b[:])))
	}
	b := a.As16()
	return inRanges(ru6, 8, binary.BigEndian.Uint64(b[:8]))
}

// inRanges reports whether v is in one of the sorted [first, last] pairs of
// width-byte numbers in t.
func inRanges(t string, width int, v uint64) bool {
	at := func(i int) uint64 {
		if width == 4 {
			return uint64(binary.BigEndian.Uint32([]byte(t[i*4 : i*4+4])))
		}
		return binary.BigEndian.Uint64([]byte(t[i*8 : i*8+8]))
	}
	n := len(t) / width / 2
	// The first pair that ends at or after v.
	i := sort.Search(n, func(i int) bool { return at(2*i+1) >= v })
	return i < n && at(2*i) <= v
}

// ruDirect reports whether host goes straight to the network as a Russian
// site: Config.RuDirect is on, host is not a delivery probe's, and no direct
// dial to it failed in the last ruDirectFor.
func (s *Switchboard) ruDirect(host string) bool {
	if !s.cfg.RuDirect {
		return false
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	ru := false
	if a, err := netip.ParseAddr(host); err == nil {
		host = a.Unmap().String()
		ru = isRuIP(a)
	} else {
		ru = isRuName(host) || s.cfg.DirectName != nil && s.cfg.DirectName(host)
	}
	if !ru {
		return false
	}
	for _, p := range s.probeHosts {
		if p == host {
			return false
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ruFailed[host] <= nowMs()
}

// serveRuDirect dials a Russian site over the device's own network, as
// serveDirect does. A failed dial is no answer to the app: it reports false,
// the site goes over the paths for ruDirectFor and the caller carries this
// flow there.
func (s *Switchboard) serveRuDirect(ctx context.Context, c net.Conn, req socksRequest) bool {
	d := wire.NewDialer(s.ruDial())
	r, err := d.DialContext(ctx, "tcp", req.String())
	if err != nil {
		if ctx.Err() == nil {
			s.ruFail(req.Host)
			s.logf("ru direct %s: %v; over the paths for %s", req, err, s.ruRetry())
		}
		return false
	}
	defer c.Close()
	s.pipeDirect(ctx, c, r)
	return true
}

func (s *Switchboard) ruDial() time.Duration {
	if s.cfg.RuDialTimeout > 0 {
		return s.cfg.RuDialTimeout
	}
	return min(s.cfg.DialTimeout, ruDialTimeout)
}

func (s *Switchboard) ruRetry() time.Duration {
	if s.cfg.RuRetryAfter > 0 {
		return s.cfg.RuRetryAfter
	}
	return ruDirectFor
}

func (s *Switchboard) ruFail(host string) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if a, err := netip.ParseAddr(host); err == nil {
		host = a.Unmap().String()
	}
	now := nowMs()
	s.mu.Lock()
	defer s.mu.Unlock()
	for h, until := range s.ruFailed {
		if until <= now {
			delete(s.ruFailed, h)
		}
	}
	s.ruFailed[host] = now + s.ruRetry().Milliseconds()
}

// openRuUDP opens the association's socket to a Russian destination over the
// device's own network. False: it cannot (the name does not resolve, say),
// and the association goes over the paths.
func (s *Switchboard) openRuUDP(ctx context.Context, a *udpAssoc, d datagram) bool {
	dctx, cancel := context.WithTimeout(ctx, s.ruDial())
	defer cancel()
	dl := wire.NewDialer(0)
	dc, err := dl.DialContext(dctx, "udp", d.to.String())
	if err != nil {
		if ctx.Err() == nil {
			s.logf("udp ru direct %s: %v", d.to, err)
		}
		return false
	}
	s.direct.Add(1)
	a.dc, a.to, a.name, a.start = dc, d.to, d.name, time.Now()
	return true
}

// pumpDirect writes the destination's datagrams back to the app until either
// side ends.
func (a *udpAssoc) pumpDirect(cancel context.CancelFunc, c net.Conn) {
	defer cancel()
	buf := make([]byte, hevUDPBuf+1) // a longer one reads cut short, and is dropped
	for {
		n, err := a.dc.Read(buf)
		if err != nil {
			return
		}
		a.last.Store(nowMs())
		src := wire.Target{}
		if ua, ok := a.dc.RemoteAddr().(*net.UDPAddr); ok {
			ap := ua.AddrPort()
			src = wire.Target{Host: ap.Addr().Unmap().String(), Port: int(ap.Port())}
		}
		from := replyFrom(src, a.to, a.name)
		if n+addrLen(from) > hevUDPBuf {
			a.overHevSize.Add(1)
			continue
		}
		if err := writeDatagram(c, from, buf[:n]); err != nil {
			return
		}
		a.answers.Add(1)
		a.down.Add(int64(n))
	}
}

// RuPrefixes4 lists the Russian IPv4 ranges as prefixes, for a firewall that
// lets the direct dials of Russian sites out (the desktop kill switch).
func RuPrefixes4() []netip.Prefix {
	var out []netip.Prefix
	for i := 0; i+8 <= len(ru4); i += 8 {
		lo := uint64(binary.BigEndian.Uint32([]byte(ru4[i : i+4])))
		hi := uint64(binary.BigEndian.Uint32([]byte(ru4[i+4 : i+8])))
		for lo <= hi {
			bits := 32
			for bits > 0 {
				size := uint64(1) << (33 - bits)
				if lo%size != 0 || lo+size-1 > hi {
					break
				}
				bits--
			}
			a := netip.AddrFrom4([4]byte{byte(lo >> 24), byte(lo >> 16), byte(lo >> 8), byte(lo)})
			out = append(out, netip.PrefixFrom(a, bits))
			lo += uint64(1) << (32 - bits)
		}
	}
	return out
}
