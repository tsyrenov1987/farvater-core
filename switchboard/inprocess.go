package switchboard

import (
	"context"
	"net"
)

// Attach readies the switchboard to serve connections handed over in process
// (ServeConn) instead of on a listening port, until ctx ends. The desktop client
// uses it: its tunnel feeds each app connection straight in, so nothing on the
// machine listens on a proxy port another program could find and use.
func (s *Switchboard) Attach(ctx context.Context) {
	s.mu.Lock()
	s.life = ctx
	s.mu.Unlock()
	go func() {
		<-ctx.Done()
		for _, w := range s.wires {
			w.Close()
		}
	}()
	s.logf("serving in process (%d paths, ctx=%s)", len(s.order), s.cfg.Ctx)
}

// ServeConn serves one SOCKS5 conversation on c — the same as a connection
// accepted on the port, credentials included — and returns when it ends.
func (s *Switchboard) ServeConn(ctx context.Context, c net.Conn) { s.handle(ctx, c) }
