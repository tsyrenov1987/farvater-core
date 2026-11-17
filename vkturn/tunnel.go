package vkturn

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// Creds are one TURN server and the credentials VK issued for it. VK's
// username is "<expiry unix>:<id>"; the server refuses an Allocate past the
// expiry (401, measured 20.10.2026).
type Creds struct {
	Address  string `json:"address"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Expiry is when the soonest of creds stops being accepted; the zero time
// when no username carries an expiry.
func Expiry(creds []Creds) time.Time {
	var t time.Time
	for _, c := range creds {
		s, _, ok := strings.Cut(c.Username, ":")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n <= 0 {
			continue
		}
		if e := time.Unix(n, 0); t.IsZero() || e.Before(t) {
			t = e
		}
	}
	return t
}

// Config says where one tunnel goes.
type Config struct {
	Server      string // the node's vkturn server, "ip:port"
	PSK         []byte // 32 bytes
	Creds       []Creds
	BitsPerChan int // pacing per relay allocation; 0: DefaultBitsPerChan
}

// DefaultBitsPerChan stays under the ~2 Mbit/s VK allows one allocation.
const DefaultBitsPerChan = 1800000

// mtu leaves room for the frame overhead and TURN ChannelData inside 1200
// bytes. It and the KCP and smux settings below match the server's.
const mtu = 1100

// Share is the part of the relay channels' paced rate that the tunnel's data
// may fill; the rest is left to KCP's headers, acks and resends. KCP runs here
// with no congestion window, so without the shaping it puts a whole send
// window in front of the pacer at once: the segments wait there longer than
// KCP's resend timeout and go out again, and a quarter of an upload is copies
// (measured 17.11.2026: 8054 resends in 32319 segments, stalls up to 2 s).
// Window is KCP's send and receive window in segments: what may sit in front
// of the pacer when a channel dies under the tunnel. Variables for the bench.
var (
	Share  = 0.85
	Window = 256
)

// shaped lets data into the KCP session no faster than its channels send.
type shaped struct {
	net.Conn
	rate   func() float64 // bytes per second the channels carry now
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

const shapedPiece = 4 << 10

func (c *shaped) Write(p []byte) (int, error) {
	done := 0
	for done < len(p) {
		n := min(len(p)-done, shapedPiece)
		c.wait(n)
		m, err := c.Conn.Write(p[done : done+n])
		done += m
		if err != nil {
			return done, err
		}
	}
	return done, nil
}

func (c *shaped) wait(n int) {
	r := c.rate() * Share
	if r <= 0 {
		return
	}
	c.mu.Lock()
	now := time.Now()
	if !c.last.IsZero() {
		c.tokens += now.Sub(c.last).Seconds() * r
	}
	if burst := r / 20; c.tokens > burst {
		c.tokens = burst
	}
	c.last = now
	c.tokens -= float64(n)
	var d time.Duration
	if c.tokens < 0 {
		d = time.Duration(-c.tokens / r * float64(time.Second))
	}
	c.mu.Unlock()
	if d > 0 {
		time.Sleep(d)
	}
}

// Resend is KCP's timers as SetNoDelay takes them: nodelay, interval, fast
// resend, no congestion window. The datagrams take the relay channels in turn
// and arrive out of order, so a resend on "a later one was acked" (fast, and
// the early one in third_party/kcp-go) fires on packets that were never lost:
// both are off, and the timeout is the slow one (from 100 ms, doubling).
var Resend = [4]int{0, 10, 0, 1}

func init() { kcp.NoEarlyRetransmit = true }

func tuneKCP(s *kcp.UDPSession) {
	s.SetNoDelay(Resend[0], Resend[1], Resend[2], Resend[3])
	s.SetWindowSize(Window, Window)
	s.SetMtu(mtu)
	s.SetStreamMode(true)
	s.SetWriteDelay(false)
}

func smuxConfig() *smux.Config {
	c := smux.DefaultConfig()
	c.KeepAliveInterval = 10 * time.Second
	c.KeepAliveTimeout = 40 * time.Second
	// Three streams' worth, as wire's h2ConnWindow: what the session holds unread
	// sits in the iOS packet tunnel's 50 MB.
	c.MaxReceiveBuffer = 6 << 20
	c.MaxStreamBuffer = 2 << 20
	return c
}

// Tunnel is one KCP+smux session over the relays: every Dial is a stream.
type Tunnel struct {
	rc   *relayConn
	sess *smux.Session
}

// Open allocates the relays and starts the session.
func Open(ctx context.Context, cfg Config) (*Tunnel, error) {
	bits := cfg.BitsPerChan
	if bits <= 0 {
		bits = DefaultBitsPerChan
	}
	rc, err := dialRelays(ctx, cfg.Server, cfg.PSK, cfg.Creds, bits)
	if err != nil {
		return nil, err
	}
	ks, err := kcp.NewConn3(1, rc.server, nil, 0, 0, rc)
	if err != nil {
		rc.Close()
		return nil, err
	}
	tuneKCP(ks)
	var conn net.Conn = ks
	if Share > 0 {
		conn = &shaped{Conn: ks, rate: func() float64 { return float64(max(rc.Channels(), 1)) * float64(bits) / 8 }}
	}
	sess, err := smux.Client(conn, smuxConfig())
	if err != nil {
		ks.Close()
		rc.Close()
		return nil, err
	}
	return &Tunnel{rc: rc, sess: sess}, nil
}

// Closed reports whether the session ended (the relays died or Close ran).
func (t *Tunnel) Closed() bool { return t.sess.IsClosed() || t.rc.closed() }

// Streams reports how many streams are open.
func (t *Tunnel) Streams() int { return t.sess.NumStreams() }

// Channels reports how many relay allocations carry the session.
func (t *Tunnel) Channels() int { return t.rc.Channels() }

// Heals reports how many relay allocations were replaced under the session.
func (t *Tunnel) Heals() int { return t.rc.Heals() }

// Close ends the tunnel, its streams and its allocations.
func (t *Tunnel) Close() error {
	t.sess.Close()
	return t.rc.Close()
}

// Dial asks the server for a TCP connection to target ("host:port"). The
// server dials only the targets it allows.
func (t *Tunnel) Dial(ctx context.Context, target string) (net.Conn, error) {
	if len(target) > 255 {
		return nil, errors.New("vkturn: target too long")
	}
	st, err := t.sess.OpenStream()
	if err != nil {
		return nil, err
	}
	dl := time.Now().Add(20 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	st.SetDeadline(dl)
	if _, err := st.Write(append([]byte{byte(len(target))}, target...)); err != nil {
		st.Close()
		return nil, err
	}
	var ok [1]byte
	if _, err := io.ReadFull(st, ok[:]); err != nil || ok[0] != 0 {
		st.Close()
		return nil, errors.New("vkturn: server could not reach " + target)
	}
	st.SetDeadline(time.Time{})
	return st, nil
}
