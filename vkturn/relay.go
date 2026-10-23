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
	lastRecv atomic.Int64 // unix nanos of the last frame of our session; born at open
}

// deadAfter failed writes in a row retire a channel; one failure may be a
// transient socket error.
const deadAfter = 5

// A relay allocation can die without a write failing: VK drops it, the
// carrier's NAT moves the phone's port, the refresh is refused. The server
// then stops hearing the channel and stops answering on it, so silence is the
// sign. A channel silent for chanSilent while another one hears the server is
// replaced; when no channel has heard anything for stallAfter, all of them are
// (smux gives up after 40 s, so the session survives that). Past giveUp the
// relays are lost and the session closes so the owner opens a new one.
// Variables only so tests can run them fast.
var (
	healEvery  = 2 * time.Second
	chanSilent = 45 * time.Second
	fresh      = 15 * time.Second
	stallAfter = 15 * time.Second
	giveUp     = 40 * time.Second
	retryFirst = 15 * time.Second
	retryMax   = 5 * time.Minute
)

// slot is one creds entry and the channel it carries, if any.
// timings are the heal knobs, copied into each conn when it opens.
type timings struct{ every, silent, fresh, stall, giveUp, retryFirst, retryMax time.Duration }

func curTimings() timings {
	return timings{healEvery, chanSilent, fresh, stallAfter, giveUp, retryFirst, retryMax}
}

type slot struct {
	creds   Creds
	fixing  bool
	nextTry time.Time
	backoff time.Duration
}

// relayConn is a net.PacketConn whose writes go out over the channels.
// The address arguments are ignored: there is only one peer, the server.
type relayConn struct {
	sealer *Sealer
	sid    SessionID
	server *net.UDPAddr
	bits   int
	chans  atomic.Pointer[[]*channel] // one per slot, nil while the slot has none; replaced, never edited
	mu     sync.Mutex                 // guards slots and swapping chans
	slots  []*slot
	heard  atomic.Int64 // unix nanos of the last frame on any channel
	in     chan []byte
	done   chan struct{}
	once   sync.Once
	rr     atomic.Uint32
	heals  atomic.Int32
	tm     timings
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
	c := &relayConn{sealer: sealer, server: srv, bits: bitsPerChan, in: make(chan []byte, 4096), done: make(chan struct{}), tm: curTimings()}
	rand.Read(c.sid[:])
	chans := make([]*channel, len(creds))
	var mu sync.Mutex
	var wg sync.WaitGroup
	abandoned := false
	for i, cr := range creds {
		c.slots = append(c.slots, &slot{creds: cr, backoff: c.tm.retryFirst})
		wg.Add(1)
		go func(i int, cr Creds) {
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
			chans[i] = ch
		}(i, cr)
	}
	all := make(chan struct{})
	go func() { wg.Wait(); close(all) }()
	select {
	case <-all:
	case <-ctx.Done():
		mu.Lock()
		abandoned = true
		for _, ch := range chans {
			if ch != nil {
				ch.close()
			}
		}
		mu.Unlock()
		return nil, ctx.Err()
	}
	up := 0
	for i, ch := range chans {
		if ch != nil {
			up++
		} else {
			c.slots[i].nextTry = time.Now().Add(c.tm.retryFirst)
		}
	}
	if up == 0 {
		return nil, errors.New("vkturn: no relay allocation came up")
	}
	c.chans.Store(&chans)
	c.heard.Store(time.Now().UnixNano())
	for _, ch := range chans {
		if ch != nil {
			c.start(ch)
		}
	}
	go c.heal()
	return c, nil
}

func (c *relayConn) start(ch *channel) {
	go c.readLoop(ch)
	go c.keepalive(ch)
}

// heal replaces the channels that died or went silent, keeping the session
// (the server keys it on sid, not on a relay address), and closes the
// session once nothing has been heard for giveUp.
func (c *relayConn) heal() {
	t := time.NewTicker(c.tm.every)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
		}
		now := time.Now()
		heard := time.Unix(0, c.heard.Load())
		if now.Sub(heard) > c.tm.giveUp {
			c.Close()
			return
		}
		stalled := now.Sub(heard) > c.tm.stall
		chans := *c.chans.Load()
		for i, ch := range chans {
			switch {
			case ch == nil, ch.dead.Load():
			case stalled && now.Sub(time.Unix(0, ch.lastRecv.Load())) > c.tm.stall:
			case now.Sub(heard) < c.tm.fresh && now.Sub(time.Unix(0, ch.lastRecv.Load())) > c.tm.silent:
			default:
				continue
			}
			c.fix(i, now)
		}
	}
}

// fix opens a new channel for slot i and swaps it in, make before break.
// A slot whose open fails waits longer each time, so creds VK no longer
// takes do not hammer the relays.
func (c *relayConn) fix(i int, now time.Time) {
	c.mu.Lock()
	sl := c.slots[i]
	if sl.fixing || now.Before(sl.nextTry) {
		c.mu.Unlock()
		return
	}
	sl.fixing = true
	c.mu.Unlock()
	go func() {
		ch, err := openChannel(sl.creds, c.server, c.bits)
		c.mu.Lock()
		defer c.mu.Unlock()
		sl.fixing = false
		select {
		case <-c.done:
			if ch != nil {
				ch.close()
			}
			return
		default:
		}
		if err != nil {
			sl.nextTry = time.Now().Add(sl.backoff)
			if sl.backoff *= 2; sl.backoff > c.tm.retryMax {
				sl.backoff = c.tm.retryMax
			}
			return
		}
		// A fresh channel gets a full chanSilent before it can be judged.
		sl.backoff, sl.nextTry = c.tm.retryFirst, time.Now().Add(c.tm.stall)
		old := *c.chans.Load()
		next := append([]*channel(nil), old...)
		next[i] = ch
		c.chans.Store(&next)
		c.heals.Add(1)
		c.start(ch)
		if old[i] != nil {
			old[i].close()
		}
	}()
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
	ch := &channel{creds: cr, underlay: pc, client: cl, relay: relay, st: NewStream(), pace: newPacer(bits)}
	ch.lastRecv.Store(time.Now().UnixNano())
	return ch, nil
}

func (ch *channel) close() {
	ch.relay.Close()
	ch.client.Close()
	ch.underlay.Close()
}

// Channels reports how many relay allocations carry the session.
func (c *relayConn) Channels() int {
	n := 0
	for _, ch := range *c.chans.Load() {
		if ch != nil && !ch.dead.Load() {
			n++
		}
	}
	return n
}

// Heals reports how many channels were replaced.
func (c *relayConn) Heals() int { return int(c.heals.Load()) }

// Stats returns bytes sent and received per slot, in creds order.
func (c *relayConn) Stats() (sent, recv []int64) {
	for _, ch := range *c.chans.Load() {
		var s, r int64
		if ch != nil {
			s, r = ch.sent.Load(), ch.recv.Load()
		}
		sent = append(sent, s)
		recv = append(recv, r)
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
	} else if ch.errs.Add(1) >= deadAfter {
		ch.dead.Store(true) // heal replaces it, or closes the session
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
		if err != nil || sid != c.sid {
			continue
		}
		now := time.Now().UnixNano()
		ch.lastRecv.Store(now)
		c.heard.Store(now)
		if len(payload) == 0 {
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
	chans := *c.chans.Load()
	start := int(c.rr.Add(1))
	var best, any *channel
	bestLevel := 0.0
	for i := 0; i < len(chans); i++ {
		ch := chans[(start+i)%len(chans)]
		if ch == nil {
			continue
		}
		if any == nil {
			any = ch
		}
		if ch.dead.Load() {
			continue
		}
		if l := ch.pace.level(); best == nil || l > bestLevel {
			best, bestLevel = ch, l
		}
	}
	if best == nil {
		best = any
	}
	return best
}

func (c *relayConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	ch := c.pick()
	if ch == nil {
		return 0, net.ErrClosed
	}
	if err := c.send(ch, p); err != nil {
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

func (c *relayConn) closed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func (c *relayConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		close(c.done)
		for _, ch := range *c.chans.Load() {
			if ch != nil {
				ch.close()
			}
		}
		c.mu.Unlock()
	})
	return nil
}

func (c *relayConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *relayConn) SetDeadline(time.Time) error      { return nil }
func (c *relayConn) SetReadDeadline(time.Time) error  { return nil }
func (c *relayConn) SetWriteDeadline(time.Time) error { return nil }
