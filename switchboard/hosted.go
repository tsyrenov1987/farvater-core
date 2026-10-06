package switchboard

import (
	"fmt"

	"github.com/tsyrenov1987/farvater-core/wire"
)

// hostedLingerMs keeps a hosted path wanted this long after it was last
// needed, so its call is not left and rejoined every few minutes.
const hostedLingerMs = 10 * 60_000

// HostedPath is a path the app runs beside the core, with what the app needs
// to run it and whether the core wants it up now.
type HostedPath struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Provider  string `json:"provider"`
	Transport string `json:"transport"`
	Options   string `json:"options,omitempty"`
	Room      string `json:"room"`
	Key       string `json:"key"`
	Want      bool   `json:"want"`
	Up        bool   `json:"up"`
}

// Hosted lists the hosted paths and whether each is wanted up now. A hosted
// call sits in a room other people share and costs traffic even idle, so it is
// wanted only on need: while the network is restricted (no path connects but
// allow-listed sites answer), while the path leads, or when the catalogue has
// nothing else; and for hostedLingerMs after. The app polls this.
func (s *Switchboard) Hosted() []HostedPath {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := nowMs()
	only := true
	for _, id := range s.order {
		if _, ok := s.wires[id].(wire.HostedWire); !ok {
			only = false
		}
	}
	var out []HostedPath
	for _, id := range s.order {
		w, ok := s.wires[id].(wire.HostedWire)
		if !ok {
			continue
		}
		if only || s.b.Restricted() || s.b.Leader() == id {
			s.wantTill[id] = now + hostedLingerMs
		}
		sp := w.Spec()
		out = append(out, HostedPath{ID: id, Kind: string(sp.Kind), Provider: sp.Provider, Transport: sp.Transport,
			Options: sp.TransportOpts, Room: sp.Room, Key: sp.Key, Want: now < s.wantTill[id], Up: w.Up()})
	}
	return out
}

// SetEndpoint hands the core a hosted path's loopback door (the app brought
// its transport up), or takes it back with the zero Endpoint (it went down).
func (s *Switchboard) SetEndpoint(id string, ep wire.Endpoint) error {
	w, ok := s.wires[id].(wire.HostedWire)
	if !ok {
		return fmt.Errorf("switchboard: %q is not a hosted path", id)
	}
	// Asleep before the door goes, awake only once it is there: no flow is
	// handed a path without one.
	if ep.Addr == "" {
		s.mu.Lock()
		s.b.Sleep(id, nowMs())
		s.mu.Unlock()
	}
	w.SetEndpoint(ep)
	if ep.Addr != "" {
		s.mu.Lock()
		s.b.Wake(id, nowMs())
		s.mu.Unlock()
	}
	return nil
}
