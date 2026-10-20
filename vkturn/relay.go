package vkturn

// relayConn spreads one KCP conversation over several TURN relay
// allocations (channels); the server gathers it back.

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/turn/v5"
)

type channel struct {
	creds    Creds
	underlay net.PacketConn
	client   *turn.Client
	relay    net.PacketConn
	st       *Stream
	pace     *pacer
	sent     atomic.Int64
	recv     atomic.Int64
	errs     atomic.Int32 // writes failed in a row
	dead     atomic.Bool  // errs hit deadAfter: the allocation is gone
}

// deadAfter failed writes in a row retire a channel; one failure may be a
// transient socket error.
const deadAfter = 5

// relayConn is a net.PacketConn whose writes go out over the channels.
// The address arguments are ignored: there is only one peer, the server.
type relayConn struct {
	sealer *Sealer
	sid    SessionID
	server *net.UDPAddr
	chans  []*channel
	in     chan []byte
	done   chan struct{}
	once   sync.Once
	rr     atomic.Uint32
	alive  atomic.Int32
}

// dialRelays opens one channel per creds entry; channels that fail are
// skipped. It gives up when ctx ends, and channels that come up after that
// are closed.
func dialRelays(ctx context.Context, server string, psk []byte, creds []Creds, bitsPerChan int) (*relayConn, error) {
	srv, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return nil, err
	}
	sealer, err := NewSealer(psk)
	if err != nil {
		return nil, err
	}
	c := &relayConn{sealer: sealer, server: srv, in: make(chan []byte, 4096), done: make(chan struct{})}
	rand.Read(c.sid[:])
	var mu sync.Mutex
	var wg sync.WaitGroup
	abandoned := false
	for _, cr := range creds {
		wg.Add(1)
		go func(cr Creds) {
			defer wg.Done()
			ch, err := openChannel(cr, srv, bitsPerChan)
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if abandoned {
				ch.close()
				return
			}
			c.chans = append(c.chans, ch)
		}(cr)
	}
	all := make(chan struct{})
	go func() { wg.Wait(); close(all) }()
	select {
	case <-all:
	case <-ctx.Done():
		mu.Lock()
		abandoned = true
		for _, ch := range c.chans {
			ch.close()
		}
		mu.Unlock()
		return nil, ctx.Err()
	}
	if len(c.chans) == 0 {
		return nil, errors.New("vkturn: no relay allocation came up")
	}
	c.alive.Store(int32(len(c.chans)))
	for _, ch := range c.chans {
		go c.readLoop(ch)
		go c.keepalive(ch)
	}
	return c, nil
}

func openChannel(cr Creds, srv *net.UDPAddr, bits int) (*channel, error) {
	pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	cl, err := turn.NewClient(&turn.ClientConfig{STUNServerAddr: cr.Address, TURNServerAddr: cr.Address,
		Username: cr.Username, Password: cr.Password, Conn: pc})
	if err != nil {
		pc.Close()
		return nil, err
	}
	if err := cl.Listen(); err != nil {
		cl.Close()
		pc.Close()
		return nil, err
	}
	relay, err := cl.Allocate()
	if err != nil {
		cl.Close()
		pc.Close()
		return nil, err
	}
	if err := cl.CreatePermission(srv); err != nil {
		relay.Close()
		cl.Close()
		pc.Close()
		return nil, err
	}
	return &channel{creds: cr, underlay: pc, client: cl, relay: relay, st: NewStream(), pace: newPacer(bits)}, nil
}

func (ch *channel) close() {
	ch.relay.Close()
	ch.client.Close()
	ch.underlay.Close()
}

// Channels reports how many relay allocations carry the session.
func (c *relayConn) Channels() int { return int(c.alive.Load()) }

// Stats returns bytes sent and received per channel, in channel order.
func (c *relayConn) Stats() (sent, recv []int64) {
	for _, ch := range c.chans {
		sent = append(sent, ch.sent.Load())
		recv = append(recv, ch.recv.Load())
	}
	return
}

func (c *relayConn) send(ch *channel, payload []byte) error {
	pkt := c.sealer.Seal(make([]byte, 0, len(payload)+Overhead), ch.st, c.sid, payload)
	ch.pace.take(len(pkt))
	ch.sent.Add(int64(len(pkt)))
	_, err := ch.relay.WriteTo(pkt, c.server)
	if err == nil {
		ch.errs.Store(0)
	} else if ch.errs.Add(1) >= deadAfter && !ch.dead.Swap(true) {
		c.alive.Add(-1)
		if c.alive.Load() <= 0 {
			// Nothing left to carry the session: close so the owner rebuilds.
			go c.Close()
		}
	}
	return err
}

func (c *relayConn) readLoop(ch *channel) {
	buf := make([]byte, 2048)
	for {
		n, _, err := ch.relay.ReadFrom(buf)
		if err != nil {
			return
		}
		ch.recv.Add(int64(n))
		sid, payload, err := c.sealer.Open(buf[:n])
		if err != nil || sid != c.sid || len(payload) == 0 {
			continue
		}
		select {
		case c.in <- append([]byte(nil), payload...):
		default:
		}
	}
}

// keepalive lets the server learn every channel's relay address and keeps
// it fresh even while the session is idle.
func (c *relayConn) keepalive(ch *channel) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		if c.send(ch, nil) != nil {
			return
		}
		select {
		case <-c.done:
			return
		case <-t.C:
		}
	}
}

// pick returns the channel with the most pacing room, starting the scan
// round-robin so equal channels share the load.
func (c *relayConn) pick() *channel {
	start := int(c.rr.Add(1))
	var best *channel
	bestLevel := 0.0
	for i := 0; i < len(c.chans); i++ {
		ch := c.chans[(start+i)%len(c.chans)]
		if ch.dead.Load() {
			continue
		}
		if l := ch.pace.level(); best == nil || l > bestLevel {
			best, bestLevel = ch, l
		}
	}
	if best == nil {
		best = c.chans[start%len(c.chans)]
	}
	return best
}

func (c *relayConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if err := c.send(c.pick(), p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *relayConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case b := <-c.in:
		return copy(p, b), c.server, nil
	case <-c.done:
		return 0, nil, net.ErrClosed
	}
}

func (c *relayConn) Close() error {
	c.once.Do(func() {
		close(c.done)
		for _, ch := range c.chans {
			ch.close()
		}
	})
	return nil
}

func (c *relayConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *relayConn) SetDeadline(time.Time) error      { return nil }
func (c *relayConn) SetReadDeadline(time.Time) error  { return nil }
func (c *relayConn) SetWriteDeadline(time.Time) error { return nil }
