package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tsyrenov1987/farvater-core/brain"
	"github.com/tsyrenov1987/farvater-core/catalogue"
	"github.com/tsyrenov1987/farvater-core/switchboard"
)

// A replaced switchboard finishes the flows open on it for at most drainMax,
// checked every drainTick; then it closes, and the apps reopen anything still
// open over the new one.
var (
	drainMax  = 10 * time.Minute
	drainTick = 5 * time.Second
)

// handoverWait is how long Reload waits for the accept loop to let the
// listener go.
const handoverWait = 2 * time.Second

var reloadMu sync.Mutex // one Reload at a time

// Reload gives the running core a fresh catalogue (its text, as
// FetchCatalogue returns it) without stopping the tunnel. The apps fetch the
// catalogue while connected and call this: a node that moved to another
// address is reached at the new one with no reconnect. When the paths are the
// same nothing changes. Otherwise a new switchboard takes over the SOCKS port
// with the same credentials and what the session has counted; flows open on
// the old one finish there. Not on a restricted network (allow-listed sites
// only): a fresh brain would have to find that out again, so the apps try
// later. Returns {"ok":true,"changed":bool,"paths":n} or {"ok":false,"error"}.
func Reload(catalogueText string) string {
	reloadMu.Lock()
	defer reloadMu.Unlock()
	fail := func(err error) string { return toJSON(map[string]any{"ok": false, "error": err.Error()}) }
	text := strings.TrimSpace(catalogueText)
	if strings.HasPrefix(text, "http://") || strings.HasPrefix(text, "https://") {
		return fail(errors.New("reload takes the catalogue text, not its address"))
	}
	cat, err := loadCatalogue(text)
	if err != nil {
		return fail(err)
	}
	mu.Lock()
	old, was := sb, running
	mu.Unlock()
	if old == nil {
		return fail(errors.New("not running"))
	}
	if samePaths(was, cat) {
		return toJSON(map[string]any{"ok": true, "changed": false, "paths": runnable(was)})
	}
	if old.Restricted() {
		return fail(errors.New("restricted network: try later"))
	}
	_ = old.SaveMemory() // the new brain starts from what the old one learned
	mu.Lock()
	cfg := config(cat, listen, user, pass, strings.TrimSuffix(old.Ctx(), brain.RestrictedSuffix))
	mu.Unlock()
	next, err := switchboard.New(cfg, cat)
	if err != nil {
		return fail(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if sb != old { // stopped meanwhile
		next.Discard()
		return fail(errors.New("not running"))
	}
	next.Inherit(old)
	ln, err := old.Detach(handoverWait)
	if err != nil {
		next.Discard()
		return fail(err)
	}
	ctx, c := context.WithCancel(context.Background())
	next.StartOn(ctx, ln)
	oldCtx, oldCancel := life, cancel
	sb, cancel, life, running = next, c, ctx, cat
	probe = cfg.ProbeURL
	if n := strings.TrimSuffix(old.Ctx(), brain.RestrictedSuffix); n != "" {
		next.SetNetwork(n) // the device moved while the new one was built
	}
	if blockedOn {
		next.SetBlocked(true)
	}
	for id, ep := range endpoints {
		_ = next.SetEndpoint(id, ep)
	}
	draining = append(draining, oldCancel)
	go drain(old, oldCtx, oldCancel)
	return toJSON(map[string]any{"ok": true, "changed": true, "paths": len(next.Paths())})
}

// drain closes a replaced switchboard once its flows are done, or after
// drainMax at the latest.
func drain(old *switchboard.Switchboard, ctx context.Context, c context.CancelFunc) {
	t := time.NewTicker(drainTick)
	defer t.Stop()
	until := time.Now().Add(drainMax)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if old.Active() == 0 || time.Now().After(until) {
			c()
			return
		}
	}
}

// samePaths reports whether two catalogues carry the same paths: the same
// ids, links and labels, in any order.
func samePaths(a, b *catalogue.Catalogue) bool {
	if a == nil || b == nil {
		return false
	}
	return slices.Equal(pathKeys(a), pathKeys(b))
}

func pathKeys(c *catalogue.Catalogue) []string {
	out := make([]string, 0, len(c.Paths))
	for _, e := range c.Paths {
		l, _ := json.Marshal(e.Labels)
		out = append(out, e.ID+"\x00"+e.URI+"\x00"+string(l))
	}
	slices.Sort(out)
	return out
}
