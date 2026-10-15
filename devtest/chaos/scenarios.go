package chaos

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/tsyrenov1987/farvater-core/mobile"
)

type scenario struct {
	name, about string
	paths       int
	net         map[int]string // #net labels by path index
	ctx         string         // network at Start
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
		if id == p.id || strings.HasSuffix(id, "#"+p.id) || strings.Contains(id, fmt.Sprintf(":%d", p.proxy.Addr().(*netAddr).Port)) {
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
		n = append(n, s.name)
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
	res := &Result{Scenario: name, Pass: true}
	t0 := time.Now()
	out := func() string {
		res.Ms = time.Since(t0).Milliseconds()
		b, _ := json.Marshal(res)
		return string(b)
	}
	if sc == nil {
		res.Pass, res.Error = false, "unknown scenario"
		return out()
	}
	res.About = sc.about
	l, err := newLab(6)
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
	if err := mobile.Start(l.catalogue(sc.net), socksPort, ctx); err != nil {
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
