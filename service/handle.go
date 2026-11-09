package service

import (
	"encoding/json"
	"fmt"
	"time"
)

type request struct {
	Op     string `json:"op"`
	Input  string `json:"input"`
	Source string `json:"source"`
	On     bool   `json:"on"`
}

func toJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"ok":false,"error":"encoding"}`)
	}
	return b
}

// Handle answers one request line from the window.
func (s *Session) Handle(line []byte) []byte {
	var r request
	if err := json.Unmarshal(line, &r); err != nil {
		return toJSON(map[string]any{"ok": false, "error": "bad request"})
	}
	switch r.Op {
	case "state":
		return toJSON(s.CurrentState())
	case "connect":
		s.Connect()
	case "disconnect":
		s.Disconnect()
	case "import":
		return toJSON(s.importSource(r.Input))
	case "save":
		return toJSON(map[string]any{"ok": s.save(r.Source)})
	case "status":
		return toJSON(map[string]any{"text": s.status()})
	case "progress":
		return toJSON(map[string]any{"text": string(toJSON(map[string]any{"bytes": s.proofRead.Load(), "total": s.proofSize.Load()}))})
	case "version":
		return toJSON(map[string]any{"text": Version})
	case "prefs":
		return toJSON(s.prefsReply())
	case "autostart":
		s.setAutostart(r.On)
	default:
		return toJSON(map[string]any{"ok": false, "error": "unknown op"})
	}
	return toJSON(map[string]any{"ok": true})
}

// importSource checks an access code or link, as the first-run dialog needs:
// one address per call, the window goes through the mirrors itself.
func (s *Session) importSource(input string) map[string]any {
	src, err := Source(input)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	f, err := s.fetchOne(src)
	if err != nil {
		e := err.Error() // the window reads "HTTP 404" here to stop trying mirrors
		if x := explained(err); x != e {
			e = fmt.Sprintf("%s (%s)", x, e)
		}
		return map[string]any{"ok": false, "error": e}
	}
	s.mu.Lock()
	s.imported = f
	s.mu.Unlock()
	out := map[string]any{"ok": true, "source": src, "paths": f.paths, "title": f.cat.Title}
	if f.provider != nil {
		out["provider"] = f.provider
	}
	return out
}

// save keeps the catalogue the last import checked, and nothing else.
func (s *Session) save(source string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.imported
	if f == nil || f.source != source {
		return false
	}
	s.imported = nil
	s.prefs.Source, s.prefs.Text, s.prefs.Title, s.prefs.Paths, s.prefs.Provider = f.source, f.text, f.cat.Title, f.paths, f.provider
	s.prefs.UpdatedMs = time.Now().UnixMilli()
	s.writePrefs()
	return true
}

func (s *Session) status() string {
	s.mu.Lock()
	l := s.live
	s.mu.Unlock()
	if l == nil {
		return "{}"
	}
	return string(toJSON(l.current().Status()))
}

func (s *Session) prefsReply() map[string]any {
	s.mu.Lock()
	p := s.prefs
	s.mu.Unlock()
	provider := ""
	if p.Provider != nil {
		provider = string(toJSON(p.Provider))
	}
	return map[string]any{"source": p.Source, "title": p.Title, "paths": p.Paths, "updatedMs": p.UpdatedMs, "provider": provider, "autostart": p.Autostart}
}

func (s *Session) setAutostart(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prefs.Autostart = on
	s.writePrefs()
}
