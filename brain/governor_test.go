package brain

import (
	"math/rand"
	"sort"
	"testing"
)

// A storm queues hundreds of handshakes on one path (an app that opens a new
// connection for every request it cannot place at once). Each one is paced
// under the switchboard's lock, so pacing must cost a few allocations, not a
// copy of the whole queue for every slot it considers.
func TestGovernorPacesALongQueueWithoutCopyingIt(t *testing.T) {
	g := NewGovernor()
	for range 400 {
		g.Acquire("s", "ip", 0)
	}
	allocs := testing.AllocsPerRun(50, func() {
		at := g.Acquire("s", "ip", 0)
		g.Release("s", "ip", at)
	})
	if allocs > 20 {
		t.Fatalf("one handshake behind 400 queued took %.0f allocations, want ≤ 20", allocs)
	}
}

// The faster pacing hands out exactly the slots the original did, through
// queues that grow, drain, share an IP across SNIs and give slots back.
func TestGovernorSlotsMatchReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	g, ref := NewGovernor(), newRefGovernor()
	type held struct {
		sni, ip string
		at      int64
	}
	var out []held
	now := int64(0)
	for i := range 5000 {
		now += int64(rng.Intn(60)) // bursts that queue slots seconds ahead
		if rng.Intn(60) == 0 {
			now += 3000 + int64(rng.Intn(10000)) // and lulls that drain them
		}
		if len(out) > 0 && rng.Intn(4) == 0 {
			k := rng.Intn(len(out))
			h := out[k]
			out = append(out[:k], out[k+1:]...)
			g.Release(h.sni, h.ip, h.at)
			ref.release(h.sni, h.ip, h.at)
			continue
		}
		sni := []string{"a", "b", "c"}[rng.Intn(3)]
		ip := map[string]string{"a": "1", "b": "1", "c": "2"}[sni]
		got, want := g.Acquire(sni, ip, now), ref.acquire(sni, ip, now)
		if got != want {
			t.Fatalf("op %d at %d (%s/%s): slot %d, reference %d", i, now, sni, ip, got, want)
		}
		out = append(out, held{sni, ip, got})
	}
}

// refGovernor is the pacing as first written: every candidate slot is checked
// against a fresh copy of the whole queue.
type refGovernor struct{ perSNI, perIP map[string][]int64 }

func newRefGovernor() *refGovernor {
	return &refGovernor{map[string][]int64{}, map[string][]int64{}}
}

func (g *refGovernor) acquire(sni, ip string, now int64) int64 {
	n, win, in, iwin := 2, int64(400), 4, int64(1000)
	g.perSNI[sni] = prune(g.perSNI[sni], now-4*max(win, iwin))
	g.perIP[ip] = prune(g.perIP[ip], now-4*max(win, iwin))
	s, p := g.perSNI[sni], g.perIP[ip]
	cands := []int64{now}
	last := now
	for _, ts := range [][]int64{s, p} {
		for _, t := range ts {
			last = max(last, t)
			for _, c := range []int64{t, t + 1, t + win, t + iwin} {
				if c >= now {
					cands = append(cands, c)
				}
			}
		}
	}
	cands = append(cands, last+max(win, iwin))
	sort.Slice(cands, func(i, j int) bool { return cands[i] < cands[j] })
	at := cands[len(cands)-1]
	for _, c := range cands {
		if refFits(s, c, n, win) && refFits(p, c, in, iwin) {
			at = c
			break
		}
	}
	g.perSNI[sni] = insertSorted(s, at)
	g.perIP[ip] = insertSorted(p, at)
	return at
}

func (g *refGovernor) release(sni, ip string, at int64) {
	g.perSNI[sni] = removeOne(g.perSNI[sni], at)
	g.perIP[ip] = removeOne(g.perIP[ip], at)
}

func refFits(ts []int64, at int64, n int, win int64) bool {
	m := insertSorted(append([]int64(nil), ts...), at)
	for i := 0; i+n < len(m); i++ {
		if m[i+n]-m[i] < win {
			return false
		}
	}
	return true
}
