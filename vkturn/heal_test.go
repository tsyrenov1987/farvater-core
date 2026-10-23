package vkturn

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/turn/v5"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// testTURN is a local TURN server that takes any of users.
func testTURN(t *testing.T, users ...string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm: "t",
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			for _, u := range users {
				if ra.Username == u {
					return u, turn.GenerateAuthKey(u, "t", "p"), true
				}
			}
			return "", nil, false
		},
		PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: pc,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return pc.LocalAddr().String()
}

// testServer speaks the node side the way orden-vkturn's server does: peers
// per session, learned from any frame, dropped after peerIdle without one.
// Relay addresses in deaf are neither heard nor answered: a silently dead
// allocation.
type testServer struct {
	pc     net.PacketConn
	sealer *Sealer
	mu     sync.Mutex
	peers  map[SessionID][]*testPeer
	deaf   map[string]bool
	rr     int
	in     chan testIn
}

type testPeer struct {
	addr net.Addr
	st   *Stream
	seen time.Time
}

type testIn struct {
	sid SessionID
	p   []byte
}

type testSessAddr SessionID

func (testSessAddr) Network() string  { return "vkturn" }
func (a testSessAddr) String() string { return string(a[:]) }

const testPeerIdle = 3 * time.Second

func newTestServer(t *testing.T, psk []byte) *testServer {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sealer, _ := NewSealer(psk)
	s := &testServer{pc: pc, sealer: sealer, peers: map[SessionID][]*testPeer{}, deaf: map[string]bool{}, in: make(chan testIn, 4096)}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			sid, payload, err := sealer.Open(buf[:n])
			if err != nil {
				continue
			}
			s.mu.Lock()
			if s.deaf[from.String()] {
				s.mu.Unlock()
				continue
			}
			found := false
			for _, p := range s.peers[sid] {
				if p.addr.String() == from.String() {
					p.seen, found = time.Now(), true
				}
			}
			if !found {
				s.peers[sid] = append(s.peers[sid], &testPeer{addr: from, st: NewStream(), seen: time.Now()})
			}
			s.mu.Unlock()
			if len(payload) > 0 {
				s.in <- testIn{sid, append([]byte(nil), payload...)}
			}
		}
	}()
	l, err := kcp.ServeConn(nil, 0, 0, s)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			ks, err := l.AcceptKCP()
			if err != nil {
				return
			}
			tuneKCP(ks)
			go func() {
				sess, err := smux.Server(ks, smuxConfig())
				if err != nil {
					return
				}
				for {
					st, err := sess.AcceptStream()
					if err != nil {
						return
					}
					go func() { // the target byte, ok, then echo
						r := bufio.NewReader(st)
						n, _ := r.ReadByte()
						io.ReadFull(r, make([]byte, n))
						st.Write([]byte{0})
						io.Copy(st, r)
					}()
				}
			}()
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return s
}

// silence makes every relay address heard so far deaf.
func (s *testServer) silence() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ps := range s.peers {
		for _, p := range ps {
			s.deaf[p.addr.String()] = true
		}
	}
}

// silenceOne makes one relay address of the session deaf.
func (s *testServer) silenceOne() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ps := range s.peers {
		for _, p := range ps {
			if !s.deaf[p.addr.String()] {
				s.deaf[p.addr.String()] = true
				return
			}
		}
	}
}

func (s *testServer) ReadFrom(p []byte) (int, net.Addr, error) {
	m, ok := <-s.in
	if !ok {
		return 0, nil, net.ErrClosed
	}
	return copy(p, m.p), testSessAddr(m.sid), nil
}

func (s *testServer) WriteTo(p []byte, addr net.Addr) (int, error) {
	sid := SessionID(addr.(testSessAddr))
	s.mu.Lock()
	var live []*testPeer
	for _, pp := range s.peers[sid] {
		if time.Since(pp.seen) < testPeerIdle && !s.deaf[pp.addr.String()] {
			live = append(live, pp)
		}
	}
	if len(live) == 0 {
		s.mu.Unlock()
		return len(p), nil
	}
	pp := live[s.rr%len(live)]
	s.rr++
	pkt := s.sealer.Seal(nil, pp.st, sid, p)
	s.mu.Unlock()
	s.pc.WriteTo(pkt, pp.addr)
	return len(p), nil
}

func (s *testServer) Close() error                     { return nil }
func (s *testServer) LocalAddr() net.Addr              { return s.pc.LocalAddr() }
func (s *testServer) SetDeadline(time.Time) error      { return nil }
func (s *testServer) SetReadDeadline(time.Time) error  { return nil }
func (s *testServer) SetWriteDeadline(time.Time) error { return nil }

func fastHeal(t *testing.T) {
	old := []time.Duration{healEvery, chanSilent, fresh, stallAfter, giveUp, retryFirst}
	healEvery, chanSilent, fresh, stallAfter, giveUp, retryFirst = 200*time.Millisecond, 3*time.Second, 2*time.Second, 2*time.Second, 30*time.Second, time.Second
	t.Cleanup(func() {
		healEvery, chanSilent, fresh, stallAfter, giveUp, retryFirst = old[0], old[1], old[2], old[3], old[4], old[5]
	})
}

// echoes writes a chunk on c and reads it back within d.
func echoes(c net.Conn, n int, d time.Duration) bool {
	msg := bytes.Repeat([]byte{byte(n)}, 4000)
	c.SetDeadline(time.Now().Add(d))
	defer c.SetDeadline(time.Time{})
	if _, err := c.Write(msg); err != nil {
		return false
	}
	got := make([]byte, len(msg))
	_, err := io.ReadFull(c, got)
	return err == nil && bytes.Equal(got, msg)
}

func openTest(t *testing.T, tweak ...func()) (*Tunnel, *testServer, net.Conn) {
	t.Helper()
	fastHeal(t)
	for _, f := range tweak {
		f()
	}
	psk := bytes.Repeat([]byte{7}, 32)
	srv := newTestServer(t, psk)
	addr := testTURN(t, "1:a", "1:b")
	tun, err := Open(context.Background(), Config{Server: srv.pc.LocalAddr().String(), PSK: psk,
		Creds: []Creds{{addr, "1:a", "p"}, {addr, "1:b", "p"}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tun.Close() })
	c, err := tun.Dial(context.Background(), "127.0.0.1:2090")
	if err != nil {
		t.Fatal(err)
	}
	if !echoes(c, 1, 5*time.Second) {
		t.Fatal("no echo before any fault")
	}
	return tun, srv, c
}

// Every allocation goes silent at once (the zone's carrier moved the
// phone's port): the session rebuilds its channels and the open stream
// carries on instead of being reset.
func TestHealAllSilent(t *testing.T) {
	tun, srv, c := openTest(t)
	srv.silence()
	if !echoes(c, 2, 20*time.Second) || tun.Closed() {
		t.Fatalf("stream did not survive: closed %v heals %d", tun.Closed(), tun.Heals())
	}
	if tun.Heals() < 2 {
		t.Fatalf("heals %d, want both channels replaced", tun.Heals())
	}
	if !echoes(c, 3, 5*time.Second) {
		t.Fatal("no echo after the heal")
	}
}

// One allocation goes silent: it is replaced and both channels carry again.
func TestHealOneSilent(t *testing.T) {
	tun, srv, c := openTest(t)
	srv.silenceOne()
	var healed atomic.Bool
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if !echoes(c, 3, 2*time.Second) {
			t.Fatal("stream broke while one channel was still good")
		}
		if tun.Heals() >= 1 && tun.Channels() == 2 {
			healed.Store(true)
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !healed.Load() {
		t.Fatalf("heals %d channels %d", tun.Heals(), tun.Channels())
	}
}

// Nothing answers for giveUp: the session closes so the owner opens anew.
func TestHealGivesUp(t *testing.T) {
	tun, srv, _ := openTest(t, func() { giveUp = 3 * time.Second })
	srv.pc.Close() // nothing will answer, not even new channels
	time.Sleep(6 * time.Second)
	if !tun.Closed() {
		t.Fatal("tunnel still open with no server")
	}
}
