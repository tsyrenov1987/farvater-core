package switchboard

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// ServeAdmin exposes /status, /journal and /receipts as JSON on addr
// (loopback only is the caller's responsibility).
func (s *Switchboard) ServeAdmin(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
	}
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, s.Status()) })
	mux.HandleFunc("/journal", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, s.Journal()) })
	mux.HandleFunc("/receipts", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, s.Receipts()) })
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
