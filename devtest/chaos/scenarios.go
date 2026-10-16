//go:build chaos

package chaos

import (
	"encoding/json"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tsyrenov1987/farvater-core/mobile"
	"github.com/tsyrenov1987/farvater-core/switchboard"
)

type scenario struct {
	name, about string
	paths       int
	net         map[int]string // #net labels by path index
	white       map[int]bool   // paths entering through an allow-listed address (JSON catalogue)
	kinds       []string       // path kinds by index (vless, trojan, kilvater, hy2); vless/trojan in turn by default
	ctx         string         // network at Start
	manual      bool           // needs a driver outside the process (sleep.sh); run by name only
	run         func(r *runner)
}

const sec = time.Second

var scenarios = []scenario{
	{name: "baseline", about: "все 6 путей здоровы", run: func(r *runner) {
		ph := r.load("смесь 4 КБ–1 МБ", 60, 4, mixed, 20*sec)
		r.check(ph.Served == ph.Requests, "доставлено %d/%d", ph.Served, ph.Requests)
		r.check(share(ph.FirstTry, ph.Requests) >= 0.98, "с первой попытки %d/%d", ph.FirstTry, ph.Requests)
	}},
	{name: "tspu_hello_rst", about: "4 из 6 путей рвут соединение RST сразу после ClientHello (ТСПУ по SNI), 2 живы", run: func(r *runner) {
		r.fault(RstHello, 0, 1, 2, 3)
		ph := r.load("страницы", 80, 4, page, 15*sec)
		r.check(share(ph.Served, ph.Requests) >= 0.98, "доставлено %d/%d", ph.Served, ph.Requests)
		r.check(r.leaderIn(4, 5), "ведущий из живых: %s", r.leaderName())
	}},
	{name: "blackhole_half", about: "3 из 6 путей глухие: принимают и молчат", run: func(r *runner) {
		r.fault(Blackhole, 0, 1, 2)
		ph := r.load("страницы", 60, 4, page, 15*sec)
		r.check(share(ph.Served, ph.Requests) >= 0.95, "доставлено %d/%d", ph.Served, ph.Requests)
		r.check(r.leaderIn(3, 4, 5), "ведущий из живых: %s", r.leaderName())
		r.check(ph.P95Ms < 12000, "p95 %d мс < 12 с", ph.P95Ms)
	}},
	{name: "leader_rst_mid", about: "прогрев, потом у ведущего RST посреди загрузки (после 48 КБ)", run: func(r *runner) {
		r.load("прогрев", 30, 3, page, 15*sec)
		victim := r.faultLeader(RstMid)
		ph := r.load("после поломки ведущего ("+victim+")", 40, 3, mixed, 20*sec)
		r.check(share(ph.Served, ph.Requests) >= 0.95, "доставлено %d/%d", ph.Served, ph.Requests)
		r.check(r.leaderName() != victim, "ведущий сменился: %s → %s", victim, r.leaderName())
	}},
	{name: "leader_freeze16k", about: "прогрев, потом ведущий замерзает после 16 КБ и держит соединение (как ТСПУ)", run: func(r *runner) {
		r.load("прогрев", 30, 3, page, 15*sec)
		victim := r.faultLeader(Freeze16K)
		ph := r.load("после заморозки ведущего ("+victim+")", 40, 3, mixed, 25*sec)
		r.check(share(ph.Served, ph.Requests) >= 0.95, "доставлено %d/%d", ph.Served, ph.Requests)
		r.check(r.leaderName() != victim, "ведущий сменился: %s → %s", victim, r.leaderName())
	}},
	{name: "throttle_most", about: "5 из 6 путей зажаты до 16 КБ/с, один быстрый", run: func(r *runner) {
		r.fault(Throttle, 0, 1, 2, 3, 4)
		r.load("страницы", 40, 4, page, 20*sec)
		ph := r.load("загрузки по 1 МБ", 12, 2, bulk, 90*sec)
		r.check(ph.Served == ph.Requests, "доставлено %d/%d", ph.Served, ph.Requests)
		r.check(r.leaderIn(5), "ведущий — быстрый путь: %s", r.leaderName())
	}},
	{name: "reels_throttled_leader", about: "лента коротких видео: ведущий и ещё 2 пути зажаты до 16 КБ/с, куски по 128 КБ (меньше порога замера скорости)", run: func(r *runner) {
		r.fault(Throttle, 0, 1, 2)
		ph := r.load("куски по 128 КБ", 24, 2, reel, 30*sec)
		r.check(ph.Served == ph.Requests, "доставлено %d/%d", ph.Served, ph.Requests)
		r.check(ph.P50Ms <= 2000, "медиана куска %d мс (≤ 2 с)", ph.P50Ms)
		r.check(r.leaderIn(3, 4, 5), "ведущий — быстрый путь: %s", r.leaderName())
	}},
	{name: "latency", about: "3 пути с задержкой +350 мс на ответ, 3 быстрых", run: func(r *runner) {
		r.fault(Latency, 0, 1, 2)
		ph := r.load("страницы", 80, 4, page, 15*sec)
		r.check(ph.Served == ph.Requests, "доставлено %d/%d", ph.Served, ph.Requests)
		r.check(r.leaderIn(3, 4, 5), "ведущий из быстрых: %s", r.leaderName())
	}},
	{name: "flaky_all", about: "на всех путях 30% соединений рвутся после ClientHello", run: func(r *runner) {
		r.fault(Flaky, 0, 1, 2, 3, 4, 5)
		ph := r.load("смесь", 80, 4, mixed, 20*sec)
		r.check(share(ph.Served, ph.Requests) >= 0.95, "доставлено %d/%d", ph.Served, ph.Requests)
	}},
	{name: "flapping", about: "60 с: каждые 4 с случайные 4 из 6 путей падают (RST на hello), остальные живы", run: func(r *runner) {
		ph := r.loadFor("мигание", 60*sec, 4, page, 15*sec, func() {
			for t := 0; t < 15; t++ {
				dead := shuffled(6)[:4]
				for i, p := range r.l.paths {
					p.set(OK)
					for _, d := range dead {
						if d == i {
							p.set(RstHello)
						}
					}
				}
				time.Sleep(4 * sec)
			}
		})
		r.check(share(ph.Served, ph.Requests) >= 0.95, "доставлено %d/%d", ph.Served, ph.Requests)
	}},
	{name: "all_dead_revive", about: "все пути рвут 20 с, потом один оживает", run: func(r *runner) {
		r.fault(Refuse, 0, 1, 2, 3, 4, 5)
		dead := r.loadFor("всё мертво", 20*sec, 2, page, 8*sec, nil)
		r.check(dead.Served == 0, "без живых путей ничего не доставлено (%d)", dead.Served)
		r.l.paths[3].set(OK)
		ph := r.loadFor("ожил p3", 30*sec, 2, page, 10*sec, nil)
		r.check(ph.RecoverMs >= 0 && ph.RecoverMs <= 15000, "связь вернулась через %d мс (≤ 15 с)", ph.RecoverMs)
		r.check(r.leaderIn(3), "ведущий — ожившая p3: %s", r.leaderName())
	}},
	{name: "storm_parallel", about: "48 параллельных загрузок: 2 пути глухие, 2 рвутся на 30%", run: func(r *runner) {
		r.fault(Blackhole, 0, 1)
		r.fault(Flaky, 2, 3)
		ph := r.load("шторм", 192, 48, mixed, 30*sec)
		r.check(share(ph.Served, ph.Requests) >= 0.95, "доставлено %d/%d", ph.Served, ph.Requests)
		r.check(r.heapMB() < 40, "куча ≤ 40 МБ (лимит Network Extension 50): %.1f", r.heapMB())
	}},
	{name: "wifi_cell_only_hint", about: "Wi-Fi: 3 пути помечены #net=cell и на Wi-Fi глухие (как CDNvideo), 3 обычных живы",
		net: map[int]string{0: "cell", 1: "cell", 2: "cell"}, ctx: "wifi", run: func(r *runner) {
			r.fault(Blackhole, 0, 1, 2)
			ph := r.load("страницы", 60, 4, page, 15*sec)
			r.check(share(ph.FirstTry, ph.Requests) >= 0.95, "с первой попытки %d/%d", ph.FirstTry, ph.Requests)
			r.check(r.leaderIn(3, 4, 5), "ведущий — обычный путь: %s", r.leaderName())
		}},
	{name: "network_switch", about: "Wi-Fi (p0–p2 мертвы) → сотовая (p3–p5 мертвы) → снова Wi-Fi", ctx: "wifi:home", run: func(r *runner) {
		r.fault(RstHello, 0, 1, 2)
		a := r.load("Wi-Fi", 40, 3, page, 15*sec)
		r.check(r.leaderIn(3, 4, 5), "на Wi-Fi ведущий из p3–p5: %s", r.leaderName())
		r.all(OK)
		r.fault(RstHello, 3, 4, 5)
		mobile.SetNetwork("cell")
		b := r.load("сотовая", 40, 3, page, 15*sec)
		r.check(r.leaderIn(0, 1, 2), "на сотовой ведущий из p0–p2: %s", r.leaderName())
		r.all(OK)
		r.fault(RstHello, 0, 1, 2)
		mobile.SetNetwork("wifi:home")
		c := r.load("снова Wi-Fi", 20, 3, page, 15*sec)
		r.check(share(c.FirstTry, c.Requests) >= share(a.FirstTry, a.Requests)-0.05,
			"возврат на Wi-Fi помнит сеть: с первой попытки %d/%d (было %d/%d)", c.FirstTry, c.Requests, a.FirstTry, a.Requests)
		r.check(share(a.Served+b.Served+c.Served, a.Requests+b.Requests+c.Requests) >= 0.97,
			"доставлено %d/%d", a.Served+b.Served+c.Served, a.Requests+b.Requests+c.Requests)
	}},
	{name: "leader_up_rst", about: "прогрев, потом у ведущего RST посреди отправки (после 64 КБ вверх)", run: func(r *runner) {
		r.load("прогрев", 30, 3, page, 15*sec)
		victim := r.faultLeader(UpRst)
		r.upload = true
		ph := r.load("отправка по 256 КБ после поломки ведущего ("+victim+")", 30, 3, []int{256 << 10}, 20*sec)
		r.check(share(ph.Served, ph.Requests) >= 0.95, "доставлено %d/%d", ph.Served, ph.Requests)
		r.check(r.leaderName() != victim, "ведущий сменился: %s → %s", victim, r.leaderName())
	}},
	{name: "leader_up_freeze", about: "прогрев, потом ведущий глотает отправку после 16 КБ и держит соединение", run: func(r *runner) {
		r.load("прогрев", 30, 3, page, 15*sec)
		victim := r.faultLeader(UpFreeze)
		r.upload = true
		ph := r.load("отправка по 256 КБ после заморозки ведущего ("+victim+")", 30, 3, []int{256 << 10}, 25*sec)
		r.check(share(ph.Served, ph.Requests) >= 0.95, "доставлено %d/%d", ph.Served, ph.Requests)
		r.check(r.leaderName() != victim, "ведущий сменился: %s → %s", victim, r.leaderName())
	}},
	{name: "jitter_all", about: "на всех путях паузы до 600 мс в 30% пачек (потери и перепосылки)", run: func(r *runner) {
		r.all(Jitter)
		ph := r.load("смесь", 80, 4, mixed, 20*sec)
		r.check(share(ph.Served, ph.Requests) >= 0.98, "доставлено %d/%d", ph.Served, ph.Requests)
		n := r.count("lead_")
		r.check(n <= 4, "ведущий не скачет: смен %d (≤ 4)", n)
	}},
	{name: "throttle_rst_most", about: "5 из 6 путей зажаты до 16 КБ/с и рвут после 48 КБ, один быстрый", run: func(r *runner) {
		r.fault(ThrottleRst, 0, 1, 2, 3, 4)
		r.load("страницы", 40, 4, page, 20*sec)
		ph := r.load("загрузки по 256 КБ", 20, 2, []int{256 << 10}, 30*sec)
		r.check(share(ph.Served, ph.Requests) >= 0.95, "доставлено %d/%d", ph.Served, ph.Requests)
		r.check(r.leaderIn(5), "ведущий — живой быстрый путь: %s", r.leaderName())
	}},
	{name: "throttle_all", about: "все 6 путей зажаты до 16 КБ/с: медленная сеть, быстрого пути нет", run: func(r *runner) {
		r.all(Throttle)
		a := r.load("страницы", 40, 4, page, 20*sec)
		b := r.load("загрузки по 256 КБ", 8, 2, []int{256 << 10}, 45*sec)
		r.check(a.Served+b.Served == a.Requests+b.Requests, "доставлено %d/%d", a.Served+b.Served, a.Requests+b.Requests)
		n := r.count("lead_")
		r.check(n <= 3, "ведущий не скачет между одинаково медленными: смен %d (≤ 3)", n)
	}},
	{name: "keepalive_freeze", about: "приложение держит соединения открытыми; ведущий замерзает под ними", run: func(r *runner) {
		r.keepAlive()
		r.load("прогрев", 30, 3, page, 15*sec)
		victim := r.faultLeader(FreezeLive)
		ph := r.load("после заморозки ведущего ("+victim+")", 40, 3, mixed, 25*sec)
		r.check(share(ph.Served, ph.Requests) >= 0.95, "доставлено %d/%d", ph.Served, ph.Requests)
		r.check(r.leaderName() != victim, "ведущий сменился: %s → %s", victim, r.leaderName())
	}},
	{name: "whitelist_cell", about: "сотовая: включились белые списки — все пути глохнут, кроме входа через разрешённый адрес (white); потом списки сняли",
		white: map[int]bool{5: true}, ctx: "cell", run: func(r *runner) {
			r.load("до списков", 20, 3, page, 15*sec)
			r.fault(Blackhole, 0, 1, 2, 3, 4)
			ph := r.load("белые списки", 60, 3, page, 15*sec)
			r.check(r.leaderIn(5), "ведущий — вход через разрешённый адрес: %s", r.leaderName())
			r.check(share(ph.Served, ph.Requests) >= 0.9, "доставлено %d/%d", ph.Served, ph.Requests)
			r.all(OK)
			after := r.load("списки сняли", 40, 3, page, 15*sec)
			r.check(share(after.Served, after.Requests) >= 0.97, "после снятия доставлено %d/%d", after.Served, after.Requests)
		}},
	{name: "kil_tspu_hello_rst", about: "кильватер: 4 из 6 путей рвут RST после ClientHello, 2 живы", kinds: []string{"kilvater", "kilvater", "kilvater", "kilvater", "kilvater", "kilvater"}, run: func(r *runner) {
		r.fault(RstHello, 0, 1, 2, 3)
		ph := r.load("страницы", 60, 4, page, 15*sec)
		r.check(share(ph.Served, ph.Requests) >= 0.98, "доставлено %d/%d", ph.Served, ph.Requests)
		r.check(r.leaderIn(4, 5), "ведущий из живых: %s", r.leaderName())
	}},
	{name: "kil_leader_freeze_live", about: "кильватер: прогрев, потом живое соединение ведущего замерзает (и новые — после 16 КБ)", kinds: []string{"kilvater", "kilvater", "kilvater", "kilvater", "kilvater", "kilvater"}, run: func(r *runner) {
		r.load("прогрев", 30, 3, page, 15*sec)
		victim := r.faultLeader(FreezeLive)
		ph := r.load("после заморозки ведущего ("+victim+")", 40, 3, mixed, 25*sec)
		r.check(share(ph.Served, ph.Requests) >= 0.95, "доставлено %d/%d", ph.Served, ph.Requests)
		r.check(r.leaderName() != victim, "ведущий сменился: %s → %s", victim, r.leaderName())
	}},
	{name: "kil_leader_rst_live", about: "кильватер: прогрев, потом живое соединение ведущего рвётся RST (и новые — после hello)", kinds: []string{"kilvater", "kilvater", "kilvater", "kilvater", "kilvater", "kilvater"}, run: func(r *runner) {
		r.load("прогрев", 30, 3, page, 15*sec)
		victim := r.faultLeader(RstLive)
		ph := r.load("после обрыва ведущего ("+victim+")", 40, 3, mixed, 20*sec)
		r.check(share(ph.Served, ph.Requests) >= 0.95, "доставлено %d/%d", ph.Served, ph.Requests)
		r.check(r.leaderName() != victim, "ведущий сменился: %s → %s", victim, r.leaderName())
	}},
	{name: "kil_throttle_most", about: "кильватер: 5 из 6 путей зажаты до 16 КБ/с, один быстрый", kinds: []string{"kilvater", "kilvater", "kilvater", "kilvater", "kilvater", "kilvater"}, run: func(r *runner) {
		r.fault(Throttle, 0, 1, 2, 3, 4)
		r.load("страницы", 40, 4, page, 20*sec)
		ph := r.load("загрузки по 256 КБ", 16, 2, []int{256 << 10}, 40*sec)
		r.check(ph.Served == ph.Requests, "доставлено %d/%d", ph.Served, ph.Requests)
		r.check(r.leaderIn(5), "ведущий — быстрый путь: %s", r.leaderName())
	}},
	{name: "hy_baseline", about: "Hysteria 2: все 6 путей здоровы", kinds: []string{"hy2", "hy2", "hy2", "hy2", "hy2", "hy2"}, run: func(r *runner) {
		ph := r.load("смесь 4 КБ–1 МБ", 60, 4, mixed, 20*sec)
		r.check(ph.Served == ph.Requests, "доставлено %d/%d", ph.Served, ph.Requests)
		n := r.count("lead_trip") + r.count("trip")
		r.check(n == 0, "здоровые пути не сняты предохранителем: срабатываний %d", n)
	}},
	{name: "hy_quic_blocked", about: "QUIC режется целиком: 3 пути Hysteria 2 глухие (пакеты дропаются), 3 TCP живы",
		kinds: []string{"hy2", "hy2", "hy2", "vless", "trojan", "vless"}, run: func(r *runner) {
			r.fault(Blackhole, 0, 1, 2)
			ph := r.load("страницы", 60, 4, page, 15*sec)
			r.check(share(ph.Served, ph.Requests) >= 0.98, "доставлено %d/%d", ph.Served, ph.Requests)
			r.check(r.leaderIn(3, 4, 5), "ведущий из TCP: %s", r.leaderName())
		}},
	{name: "hy_leader_drop_live", about: "Hysteria 2: прогрев, потом у ведущего пропадают все пакеты посреди сессии", kinds: []string{"hy2", "hy2", "hy2", "hy2", "hy2", "hy2"}, run: func(r *runner) {
		r.load("прогрев", 30, 3, page, 15*sec)
		victim := r.faultLeader(RstLive)
		ph := r.load("после обрыва ведущего ("+victim+")", 40, 3, mixed, 20*sec)
		r.check(share(ph.Served, ph.Requests) >= 0.95, "доставлено %d/%d", ph.Served, ph.Requests)
		r.check(r.leaderName() != victim, "ведущий сменился: %s → %s", victim, r.leaderName())
	}},
	{name: "hy_freeze16k", about: "Hysteria 2: прогрев, потом ведущий пропускает 16 КБ сессии и замолкает", kinds: []string{"hy2", "hy2", "hy2", "hy2", "hy2", "hy2"}, run: func(r *runner) {
		r.load("прогрев", 30, 3, page, 15*sec)
		victim := r.faultLeader(FreezeLive)
		ph := r.load("после заморозки ведущего ("+victim+")", 40, 3, mixed, 25*sec)
		r.check(share(ph.Served, ph.Requests) >= 0.95, "доставлено %d/%d", ph.Served, ph.Requests)
		r.check(r.leaderName() != victim, "ведущий сменился: %s → %s", victim, r.leaderName())
	}},
	{name: "hy_throttle_most", about: "Hysteria 2: 5 из 6 путей зажаты до 16 КБ/с, один быстрый", kinds: []string{"hy2", "hy2", "hy2", "hy2", "hy2", "hy2"}, run: func(r *runner) {
		r.fault(Throttle, 0, 1, 2, 3, 4)
		r.load("страницы", 40, 4, page, 20*sec)
		ph := r.load("загрузки по 256 КБ", 16, 2, []int{256 << 10}, 40*sec)
		r.check(ph.Served == ph.Requests, "доставлено %d/%d", ph.Served, ph.Requests)
		r.check(r.leaderIn(5), "ведущий — быстрый путь: %s", r.leaderName())
	}},
	{name: "whitelist_all_silent", about: "сотовая: белые списки глушат все пути 20 с, потом пропускают только вход через разрешённый адрес (white)",
		white: map[int]bool{5: true}, ctx: "cell", run: func(r *runner) {
			r.load("до списков", 20, 3, page, 15*sec)
			r.all(Blackhole)
			r.loadFor("всё глухо", 20*sec, 2, page, 8*sec, nil)
			on := r.count("restricted_on")
			r.check(on >= 1, "ядро поняло, что сеть жива, а пути заглушены (restricted_on %d)", on)
			r.l.paths[5].set(OK)
			ph := r.loadFor("пропускают white-вход p5", 30*sec, 2, page, 10*sec, nil)
			r.check(ph.RecoverMs >= 0 && ph.RecoverMs <= 15000, "связь вернулась через %d мс (≤ 15 с)", ph.RecoverMs)
			r.check(r.leaderIn(5), "ведущий — white-вход: %s", r.leaderName())
		}},
	{name: "soak_15min", about: "15 мин нагрузки; каждые 2 мин на 2–4 случайных путях случайная помеха, хотя бы один путь жив", run: func(r *runner) {
		r.load("прогрев", 20, 3, page, 15*sec)
		g0 := runtime.NumGoroutine()
		faults := []Fault{RstHello, Blackhole, RstMid, Freeze16K, Throttle, Latency, Flaky, Jitter, UpRst, ThrottleRst, FreezeLive, RstLive}
		ph := r.loadFor("15 минут", 15*time.Minute, 3, mixed, 30*sec, func() {
			for t := 0; t < 7; t++ {
				r.all(OK)
				idx := shuffled(6)[:2+mrand.IntN(3)]
				for _, i := range idx {
					r.l.paths[i].set(faults[mrand.IntN(len(faults))])
				}
				time.Sleep(2 * time.Minute)
			}
		})
		r.all(OK)
		r.check(share(ph.Served, ph.Requests) >= 0.95, "доставлено %d/%d", ph.Served, ph.Requests)
		r.check(r.heapMB() < 40, "куча ≤ 40 МБ: %.1f", r.heapMB())
		time.Sleep(5 * sec)
		g1 := runtime.NumGoroutine()
		r.check(g1-g0 < 200, "горутины не текут: было %d, стало %d", g0, g1)
	}},
	{name: "idle_resume", about: "прогрев, минута тишины, за это время ведущий умер (RST на hello); потом трафик", run: func(r *runner) {
		r.load("прогрев", 30, 3, page, 15*sec)
		victim := r.faultLeader(RstHello)
		time.Sleep(60 * sec)
		ph := r.load("после тишины", 40, 3, page, 15*sec)
		r.check(share(ph.Served, ph.Requests) >= 0.97, "доставлено %d/%d", ph.Served, ph.Requests)
		r.check(ph.RecoverMs >= 0 && ph.RecoverMs <= 5000, "связь с первой попытки через %d мс (≤ 5 с)", ph.RecoverMs)
		r.check(r.leaderName() != victim, "ведущий сменился: %s → %s", victim, r.leaderName())
	}},
	{name: "sleep_wake", about: "сон телефона: загрузки идут, процесс замирает на 60 с (снаружи, sleep.sh), за это время сеть забыла все живые соединения (NAT); потом просыпается",
		manual: true, run: func(r *runner) {
			r.keepAlive()
			r.load("прогрев", 30, 3, page, 15*sec)
			leader := r.leaderName()
			var slept time.Duration
			ph := r.loadFor("сон посреди загрузок", 100*sec, 3, mixed, 20*sec, func() {
				time.Sleep(15 * sec)
				slept = r.sleep(60*sec, func() {
					for _, p := range r.l.paths {
						p.epoch.Add(1)
					}
				})
			})
			r.check(slept >= 50*sec, "процесс спал %d с (≥ 50)", int(slept.Seconds()))
			r.check(share(ph.Served, ph.Requests) >= 0.95, "загрузки, пережившие сон: доставлено %d/%d", ph.Served, ph.Requests)
			after := r.load("после сна", 40, 3, page, 15*sec)
			r.check(share(after.Served, after.Requests) >= 0.97, "после сна доставлено %d/%d", after.Served, after.Requests)
			r.check(after.RecoverMs >= 0 && after.RecoverMs <= 5000, "связь с первой попытки через %d мс (≤ 5 с)", after.RecoverMs)
			n := r.count("lead_trip")
			r.check(n == 0, "здоровые пути не выбиты предохранителем после сна: срабатываний %d (ведущий был %s, стал %s)", n, leader, r.leaderName())
		}},
}

// sleep asks sleep.sh, outside the process, to stop it for d as iOS suspends
// an app, and returns the longest pause it saw; 0 when no one stopped it.
// woke runs as soon as the process sees it slept: what the network did
// meanwhile.
func (r *runner) sleep(d time.Duration, woke func()) time.Duration {
	switchboard.SetLabSleep(time.Now(), d)
	f := filepath.Join(os.TempDir(), "chaos-sleep")
	_ = os.WriteFile(f, []byte(fmt.Sprintf("%d %d\n", os.Getpid(), int(d.Seconds()))), 0o644)
	defer os.Remove(f)
	var most time.Duration
	last := time.Now()
	for end := last.Add(d + 30*sec); time.Now().Before(end); {
		time.Sleep(100 * time.Millisecond)
		if gap := time.Since(last); gap > most {
			most = gap
		}
		last = time.Now()
		if most > d/2 {
			woke()
			break
		}
	}
	return most
}

// count counts the core's journal entries whose act starts with prefix.
func (r *runner) count(prefix string) int {
	var j []struct{ Act string }
	_ = json.Unmarshal([]byte(mobile.JournalJSON()), &j)
	n := 0
	for _, e := range j {
		if strings.HasPrefix(e.Act, prefix) {
			n++
		}
	}
	return n
}

func (r *runner) fault(f Fault, idx ...int) {
	for _, i := range idx {
		r.l.paths[i].set(f)
	}
}

func (r *runner) all(f Fault) {
	for _, p := range r.l.paths {
		p.set(f)
	}
}

// leaderName maps the core's leader id to the lab's path name.
func (r *runner) leaderName() string {
	id := r.leader()
	for _, p := range r.l.paths {
		if id == p.id || strings.HasSuffix(id, "#"+p.id) || strings.Contains(id, fmt.Sprintf(":%d", p.port())) {
			return p.id
		}
	}
	return id
}

func (r *runner) leaderIn(idx ...int) bool {
	name := r.leaderName()
	for _, i := range idx {
		if r.l.paths[i].id == name {
			return true
		}
	}
	return false
}

func (r *runner) faultLeader(f Fault) string {
	name := r.leaderName()
	for _, p := range r.l.paths {
		if p.id == name {
			p.set(f)
		}
	}
	return name
}

var runMu sync.Mutex

// Scenarios lists the scenario names, comma separated.
func Scenarios() string {
	var n []string
	for _, s := range scenarios {
		if !s.manual {
			n = append(n, s.name)
		}
	}
	return strings.Join(n, ",")
}

// Run runs one scenario against the real core and returns its Result as JSON.
func Run(name string) string {
	runMu.Lock()
	defer runMu.Unlock()
	var sc *scenario
	for i := range scenarios {
		if scenarios[i].name == name {
			sc = &scenarios[i]
		}
	}
	res := &Result{Scenario: name, Pass: true, Sweep: os.Getenv("CHAOS_SWEEP")}
	t0 := time.Now()
	probeBytes.Store(0)
	out := func() string {
		res.Ms = time.Since(t0).Milliseconds()
		res.ProbeKB = probeBytes.Load() >> 10
		b, _ := json.Marshal(res)
		return string(b)
	}
	if sc == nil {
		res.Pass, res.Error = false, "unknown scenario"
		return out()
	}
	res.About = sc.about
	l, err := newLab(6, sc.kinds)
	if err != nil {
		res.Pass, res.Error = false, err.Error()
		return out()
	}
	defer l.close()
	ctx := sc.ctx
	if ctx == "" {
		ctx = "chaos"
	}
	mobile.SetMemoryFile("")
	switchboard.SetLabTune(labTune)
	cat := l.catalogue(sc.net)
	if sc.white != nil {
		cat = l.catalogueJSON(sc.white)
	}
	if err := mobile.Start(cat, socksPort, ctx); err != nil {
		res.Pass, res.Error = false, "start: "+err.Error()
		return out()
	}
	defer mobile.Stop()
	r, err := newRunner(l, res)
	if err != nil {
		res.Pass, res.Error = false, err.Error()
		return out()
	}
	sc.run(r)
	r.finish()
	return out()
}

// probeBytes counts what the origin was asked for by sweeps' probes.
var probeBytes atomic.Int64

// labTune sets the core up for the lab: its probe is the lab's origin, and
// CHAOS_SWEEP picks the sweep settings compared: off, doubt (the core's
// default) or every10 (every path every 10 s, doubt or not).
func labTune(c *switchboard.Config) {
	c.ProbeURL = "https://probe.chaos.test/bytes?n=262144"
	switch os.Getenv("CHAOS_SWEEP") {
	case "off":
		c.Brain.SweepMs = 0
	case "every10":
		c.Brain.SweepMs, c.Brain.SweepAlways, c.Brain.SweepMax = 10_000, true, 0
	}
}
