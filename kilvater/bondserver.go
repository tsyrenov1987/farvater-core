package kilvater

import (
	"context"
	"encoding/hex"
	"io"
	"sync"
	"time"
)

// bondIdle is how long a bond with no legs waits for one to rejoin before it
// is dropped and its target closed.
var bondIdle = 30 * time.Second

// bondMax caps the bonds one server holds at once.
const bondMax = 4096

type srvBond struct {
	b     *Bond
	ready chan struct{} // closed once the target is dialed (or failed)
	ok    bool
	legs  int
	idle  *time.Timer
}

type bondTable struct {
	mu sync.Mutex
	m  map[string]*srvBond
}

var bonds = &bondTable{m: map[string]*srvBond{}}

type legRW struct {
	io.Reader
	io.Writer
	body io.Closer
}

func (l *legRW) Close() error { return l.body.Close() }

// join serves one leg of a bond (a stream whose first frame was JOIN). The
// bond is keyed by the key's label and the client's session id, so one key
// can never reach another's flow. The first leg with JoinCreate dials the
// target; the others attach to it.
func (s *Server) join(label string, body []byte, up io.ReadCloser, down io.Writer, ks *keyStat) {
	sid, flags, network, addr, err := ParseJoin(body)
	if err != nil {
		return
	}
	if network != NetTCP {
		WriteFrame(down, FrameClose, []byte{1})
		return
	}
	key := label + "/" + hex.EncodeToString(sid[:])

	bonds.mu.Lock()
	sb := bonds.m[key]
	creator := false
	if sb == nil {
		if flags&JoinCreate == 0 || len(bonds.m) >= bondMax {
			bonds.mu.Unlock()
			WriteFrame(down, FrameClose, []byte{2}) // no such bond
			return
		}
		sb = &srvBond{b: NewBond(), ready: make(chan struct{})}
		bonds.m[key] = sb
		creator = true
	}
	sb.legs++
	if sb.idle != nil {
		sb.idle.Stop()
		sb.idle = nil
	}
	bonds.mu.Unlock()

	defer func() {
		bonds.mu.Lock()
		sb.legs--
		if sb.legs == 0 && bonds.m[key] == sb {
			sb.idle = time.AfterFunc(bondIdle, func() {
				bonds.mu.Lock()
				drop := sb.legs == 0 && bonds.m[key] == sb
				if drop {
					delete(bonds.m, key)
				}
				bonds.mu.Unlock()
				if drop {
					sb.b.Abort(1, errBondClosed)
				}
			})
		}
		bonds.mu.Unlock()
	}()

	if creator {
		go s.bondTarget(key, sb, addr, ks)
	}
	select {
	case <-sb.ready:
	case <-time.After(30 * time.Second):
		return
	}
	if !sb.ok {
		WriteFrame(down, FrameClose, []byte{1})
		return
	}
	sb.b.RunLeg(&legRW{Reader: up, Writer: down, body: up}, true)
}

// bondTarget dials the bond's target and pumps it to and from the bond until
// both directions end, then drops the bond.
func (s *Server) bondTarget(key string, sb *srvBond, addr string, ks *keyStat) {
	defer func() {
		bonds.mu.Lock()
		if bonds.m[key] == sb {
			delete(bonds.m, key)
		}
		bonds.mu.Unlock()
	}()
	dial := s.dialer().DialContext
	if s.Dial != nil {
		dial = s.Dial
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	remote, err := dial(ctx, "tcp", addr)
	cancel()
	if err != nil {
		s.log("bond dial %s: %v", addr, err)
		close(sb.ready)
		sb.b.Abort(1, err)
		return
	}
	defer remote.Close()
	sb.ok = true
	close(sb.ready)
	b := sb.b
	go func() { <-b.quit; remote.Close() }() // the bond ended: free the target

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // target -> client
		defer wg.Done()
		p := make([]byte, 32*1024)
		for {
			n, err := remote.Read(p)
			if n > 0 {
				if _, werr := b.Write(p[:n]); werr != nil {
					remote.Close()
					return
				}
				ks.addDown(n)
			}
			if err != nil {
				b.CloseWrite()
				return
			}
		}
	}()
	go func() { // client -> target
		defer wg.Done()
		p := make([]byte, 32*1024)
		for {
			n, err := b.Read(p)
			if n > 0 {
				if _, werr := remote.Write(p[:n]); werr != nil {
					b.Abort(1, werr)
					return
				}
				ks.addUp(n)
			}
			if err == io.EOF {
				closeWrite(remote)
				return
			}
			if err != nil {
				remote.Close()
				return
			}
		}
	}()
	wg.Wait()
	b.Drain(10 * time.Second)
	b.Close()
}
