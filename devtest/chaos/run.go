package chaos

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"

	"github.com/tsyrenov1987/farvater-core/mobile"
)

var socksPort = 11190

// Phase is one stretch of load under one set of faults.
type Phase struct {
	Name      string  `json:"name"`
	Requests  int     `json:"requests"`
	Served    int     `json:"served"`    // succeeded, retries included (what the user sees)
	FirstTry  int     `json:"first_try"` // succeeded on the first attempt
	Attempts  int     `json:"attempts"`  // attempts made in all
	P50Ms     int64   `json:"p50_ms"`    // request time, retries included
	P95Ms     int64   `json:"p95_ms"`
	MaxMs     int64   `json:"max_ms"`
	MBps      float64 `json:"mbps"`       // payload over wall time of the phase
	RecoverMs int64   `json:"recover_ms"` // until three first-try successes in a row; -1 never
}

// Result is a scenario's report.
type Result struct {
	Scenario string   `json:"scenario"`
	About    string   `json:"about"`
	Phases   []Phase  `json:"phases"`
	Leaders  []string `json:"leaders"` // leader changes, "t+ms path"
	Journal  []string `json:"journal"` // the core's decision journal, "t+ms act path: why"
	Conns    []string `json:"conns"`   // connections each path's proxy took, with its last fault
	Bad      []string `json:"bad"`     // receipts that failed, stalled or ran over 5 s, "t+ms path end down=… stalls=… dur=…"
	Flows    int64    `json:"flows"`
	Retries  int64    `json:"retries"`
	HeapMB   float64  `json:"heap_peak_mb"`
	Pass     bool     `json:"pass"`
	Checks   []string `json:"checks"`
	Error    string   `json:"error,omitempty"`
	Ms       int64    `json:"ms"`
}

type runner struct {
	l       *lab
	res     *Result
	t0      time.Time
	client  *http.Client
	stop    chan struct{}
	heap    atomic.Uint64
	samples sync.WaitGroup
}

func (r *runner) check(ok bool, format string, a ...any) {
	mark := "✅ "
	if !ok {
		mark = "❌ "
		r.res.Pass = false
	}
	r.res.Checks = append(r.res.Checks, mark+fmt.Sprintf(format, a...))
}

func newRunner(l *lab, res *Result) (*runner, error) {
	d, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort),
		&proxy.Auth{User: mobile.SocksUser(), Password: mobile.SocksPass()}, proxy.Direct)
	if err != nil {
		return nil, err
	}
	cd := d.(proxy.ContextDialer)
	tr := &http.Transport{DialContext: func(ctx context.Context, n, a string) (net.Conn, error) { return cd.DialContext(ctx, n, a) },
		DisableKeepAlives: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	r := &runner{l: l, res: res, t0: time.Now(), client: &http.Client{Transport: tr}, stop: make(chan struct{})}
	r.samples.Add(1)
	go r.sample()
	return r, nil
}

// sample records leader changes and the heap peak.
func (r *runner) sample() {
	defer r.samples.Done()
	last := ""
	var ms runtime.MemStats
	for {
		var st struct{ Leader string }
		_ = json.Unmarshal([]byte(mobile.StatusJSON()), &st)
		if st.Leader != last {
			r.res.Leaders = append(r.res.Leaders, fmt.Sprintf("t+%d %s", time.Since(r.t0).Milliseconds(), st.Leader))
			last = st.Leader
		}
		runtime.ReadMemStats(&ms)
		if ms.HeapInuse > r.heap.Load() {
			r.heap.Store(ms.HeapInuse)
		}
		select {
		case <-r.stop:
			return
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (r *runner) leader() string {
	var st struct{ Leader string }
	_ = json.Unmarshal([]byte(mobile.StatusJSON()), &st)
	return st.Leader
}

// get fetches n bytes from a site as an app would: a new connection, and up
// to three attempts when one fails.
func (r *runner) get(site int, n int, timeout time.Duration) (ok, first bool, attempts int, ms int64, got int64) {
	start := time.Now()
	for attempts = 1; attempts <= 3; attempts++ {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://site%d.chaos.test:443/bytes?n=%d", site, n), nil)
		resp, err := r.client.Do(req)
		if err == nil {
			var k int64
			k, err = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			got += k
			if err == nil && k != int64(n) {
				err = io.ErrUnexpectedEOF
			}
		}
		cancel()
		if err == nil {
			return true, attempts == 1, attempts, time.Since(start).Milliseconds(), got
		}
	}
	return false, false, 3, time.Since(start).Milliseconds(), got
}

// load runs count requests with conc in flight; sizes are picked in turn.
func (r *runner) load(name string, count, conc int, sizes []int, timeout time.Duration) Phase {
	ph := Phase{Name: name, Requests: count, RecoverMs: -1}
	var mu sync.Mutex
	var times []int64
	var bytes int64
	streak := 0
	start := time.Now()
	next := atomic.Int64{}
	var wg sync.WaitGroup
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= count {
					return
				}
				ok, first, att, ms, got := r.get(i%7, sizes[i%len(sizes)], timeout)
				mu.Lock()
				ph.Attempts += att
				bytes += got
				times = append(times, ms)
				if ok {
					ph.Served++
				}
				if first {
					ph.FirstTry++
					streak++
					if streak == 3 && ph.RecoverMs < 0 {
						ph.RecoverMs = time.Since(start).Milliseconds()
					}
				} else {
					streak = 0
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	slices.Sort(times)
	if len(times) > 0 {
		ph.P50Ms = times[len(times)/2]
		ph.P95Ms = times[len(times)*95/100]
		ph.MaxMs = times[len(times)-1]
	}
	if s := time.Since(start).Seconds(); s > 0 {
		ph.MBps = float64(int64(float64(bytes)/s/1e4)) / 100
	}
	r.res.Phases = append(r.res.Phases, ph)
	return ph
}

// loadFor runs requests for d with conc in flight.
func (r *runner) loadFor(name string, d time.Duration, conc int, sizes []int, timeout time.Duration, during func()) Phase {
	// a count large enough for d; the phase ends early when d runs out
	ph := Phase{Name: name, RecoverMs: -1}
	var mu sync.Mutex
	var times []int64
	var bytes int64
	streak := 0
	start := time.Now()
	deadline := start.Add(d)
	var wg sync.WaitGroup
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; time.Now().Before(deadline); i += conc {
				ok, first, att, ms, got := r.get(i%7, sizes[i%len(sizes)], timeout)
				mu.Lock()
				ph.Requests++
				ph.Attempts += att
				bytes += got
				times = append(times, ms)
				if ok {
					ph.Served++
				}
				if first {
					ph.FirstTry++
					streak++
					if streak == 3 && ph.RecoverMs < 0 {
						ph.RecoverMs = time.Since(start).Milliseconds()
					}
				} else {
					streak = 0
				}
				mu.Unlock()
			}
		}(w)
	}
	if during != nil {
		go during()
	}
	wg.Wait()
	slices.Sort(times)
	if len(times) > 0 {
		ph.P50Ms = times[len(times)/2]
		ph.P95Ms = times[len(times)*95/100]
		ph.MaxMs = times[len(times)-1]
	}
	if s := time.Since(start).Seconds(); s > 0 {
		ph.MBps = float64(int64(float64(bytes)/s/1e4)) / 100
	}
	r.res.Phases = append(r.res.Phases, ph)
	return ph
}

func (r *runner) finish() {
	close(r.stop)
	r.samples.Wait()
	var st struct {
		Flows, Retries int64
		Paths          []struct {
			ID         string `json:"id"`
			GoodputBps int64  `json:"goodput_bps"`
		}
	}
	_ = json.Unmarshal([]byte(mobile.StatusJSON()), &st)
	speed := map[string]int64{}
	for _, p := range st.Paths {
		speed[p.ID] = p.GoodputBps
	}
	r.res.Flows, r.res.Retries = st.Flows, st.Retries
	var j []struct {
		AtMs           int64
		Act, Why, Path string
	}
	_ = json.Unmarshal([]byte(mobile.JournalJSON()), &j)
	for _, e := range j {
		r.res.Journal = append(r.res.Journal, fmt.Sprintf("t+%d %s %s: %s", e.AtMs-r.t0.UnixMilli(), e.Act, e.Path, e.Why))
	}
	var rs []struct {
		At     int64  `json:"at_ms"`
		Path   string `json:"path"`
		End    string `json:"end"`
		Down   int64  `json:"down"`
		DurMs  int64  `json:"dur_ms"`
		Stalls int    `json:"stalls"`
		AnsMs  int64  `json:"answer_ms"`
	}
	_ = json.Unmarshal([]byte(mobile.ReceiptsJSON()), &rs)
	fb := map[string][]int64{}
	for _, e := range rs {
		if e.AnsMs > 0 {
			fb[e.Path] = append(fb[e.Path], e.AnsMs)
		}
		if (e.End != "remote_fin" && e.End != "local_close") || e.Stalls > 0 || e.DurMs > 5000 {
			r.res.Bad = append(r.res.Bad, fmt.Sprintf("t+%d %s %s down=%d stalls=%d dur=%d", e.At-r.t0.UnixMilli(), e.Path, e.End, e.Down, e.Stalls, e.DurMs))
		}
	}
	for _, p := range r.l.paths {
		var med int64 = -1
		if t := fb[p.id]; len(t) > 0 {
			slices.Sort(t)
			med = t[len(t)/2]
		}
		r.res.Conns = append(r.res.Conns, fmt.Sprintf("%s %s: %d (%s) %d KB/s, answer p50 %d ms of %d", p.id, p.kind, p.conns.Load(), p.get(), speed[p.id]>>10, med, len(fb[p.id])))
	}
	r.res.HeapMB = r.heapMB()
}

func (r *runner) heapMB() float64 { return float64(r.heap.Load()>>10) / 1024 }

func share(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

var (
	page  = []int{4 << 10, 24 << 10, 8 << 10}
	mixed = []int{4 << 10, 256 << 10, 24 << 10, 1 << 20, 8 << 10}
	bulk  = []int{1 << 20}
)

func shuffled(n int) []int {
	p := rand.Perm(n)
	return p
}
