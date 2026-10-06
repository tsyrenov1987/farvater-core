package switchboard

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/wire"
)

// The frames are hev-socks5-tunnel's UDP-in-TCP layout, byte for byte:
// [data length u16][3 + address length][SOCKS5 address][data].
func TestUDPFrames(t *testing.T) {
	v4 := []byte{0, 4, 10, 1, 1, 1, 1, 1, 0, 53, 'p', 'i', 'n', 'g'}
	d, err := readDatagram(bytes.NewReader(v4))
	if err != nil || d.to != (wire.Target{Host: "1.1.1.1", Port: 53}) || d.name || string(d.data) != "ping" {
		t.Fatalf("ipv4 frame: %+v %v", d, err)
	}
	name := []byte{0, 2, 3 + 4 + 5, 3, 5, 'a', '.', 'b', 'c', 'd', 0x0d, 0x96, 'h', 'i'}
	if d, err = readDatagram(bytes.NewReader(name)); err != nil || d.to != (wire.Target{Host: "a.bcd", Port: 3478}) || !d.name || string(d.data) != "hi" {
		t.Fatalf("name frame: %+v %v", d, err)
	}
	v6 := append([]byte{0, 1, 22, 4}, netip.MustParseAddr("2001:db8::1").AsSlice()...)
	v6 = append(v6, 0x01, 0xbb, 'x')
	if d, err = readDatagram(bytes.NewReader(v6)); err != nil || d.to != (wire.Target{Host: "2001:db8::1", Port: 443}) || string(d.data) != "x" {
		t.Fatalf("ipv6 frame: %+v %v", d, err)
	}
	for _, bad := range [][]byte{
		{0, 1, 6, 1, 1, 1, 1, 0, 'x'},               // header length too short for any address
		{0, 1, 11, 1, 1, 1, 1, 1, 0, 53, 'x'},       // IPv4 with a stray address byte
		{0, 1, 10, 9, 1, 1, 1, 1, 0, 53, 'x'},       // unknown address type
		{0, 1, 10, 3, 9, 'a', '.', 'b', 0, 53, 'x'}, // a name longer than its address
	} {
		if _, err := readDatagram(bytes.NewReader(bad)); err == nil {
			t.Fatalf("bad frame %v read", bad)
		}
	}
	var out bytes.Buffer
	if err := writeDatagram(&out, netip.MustParseAddrPort("1.1.1.1:53"), []byte("ping")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), v4) {
		t.Fatalf("written %v, want %v", out.Bytes(), v4)
	}
	out.Reset()
	_ = writeDatagram(&out, netip.MustParseAddrPort("[2001:db8::1]:443"), []byte("x"))
	if !bytes.Equal(out.Bytes(), v6) {
		t.Fatalf("written %v, want %v", out.Bytes(), v6)
	}
}

// A reply goes back as an IP hev can deliver from: its own source when that is
// an IP of the destination's family, else the destination. A named destination
// takes any IP, since hev answers from the mapped address anyway.
func TestReplyFrom(t *testing.T) {
	dst := wire.Target{Host: "1.1.1.1", Port: 53}
	for _, c := range []struct {
		src  wire.Target
		to   wire.Target
		name bool
		want string
	}{
		{wire.Target{Host: "1.0.0.1", Port: 5353}, dst, false, "1.0.0.1:5353"},
		{wire.Target{Host: "::ffff:1.0.0.1", Port: 53}, dst, false, "1.0.0.1:53"},
		{wire.Target{Host: "2001:db8::1", Port: 53}, dst, false, "1.1.1.1:53"},
		{wire.Target{}, dst, false, "1.1.1.1:53"},
		{wire.Target{Host: "example.com", Port: 53}, dst, false, "1.1.1.1:53"},
		{wire.Target{Host: "2001:db8::1", Port: 3478}, wire.Target{Host: "stun.example", Port: 3478}, true, "[2001:db8::1]:3478"},
		{wire.Target{}, wire.Target{Host: "stun.example", Port: 3478}, true, "0.0.0.0:3478"},
	} {
		if got := replyFrom(c.src, c.to, c.name).String(); got != c.want {
			t.Errorf("replyFrom(%v, %v, %v) = %s, want %s", c.src, c.to, c.name, got, c.want)
		}
	}
}

// fakeUDPWire is a path that carries only UDP, through sessions it makes.
type fakeUDPWire struct {
	id      string
	dialErr error
	dials   atomic.Int32
	newSess func() wire.PacketSession
}

func (w *fakeUDPWire) ID() string           { return w.id }
func (w *fakeUDPWire) Spec() wire.PathSpec  { return wire.PathSpec{ID: w.id} }
func (w *fakeUDPWire) NeedsHandshake() bool { return false }
func (w *fakeUDPWire) Close() error         { return nil }
func (w *fakeUDPWire) Dial(context.Context) (wire.Session, error) {
	return nil, errors.New("no TCP here")
}
func (w *fakeUDPWire) DialPacket(context.Context) (wire.PacketSession, error) {
	w.dials.Add(1)
	if w.dialErr != nil {
		return nil, w.dialErr
	}
	return w.newSess(), nil
}

type pkt struct {
	data []byte
	addr wire.Target
}

// echoSession returns every datagram from where it was sent; silent (no echo)
// keeps them; refusing ends at once, as a server that will not carry UDP.
type echoSession struct {
	ch        chan pkt
	silent    bool
	refusing  bool
	closed    chan struct{}
	closeOnce sync.Once
}

func newEcho() *echoSession { return &echoSession{ch: make(chan pkt, 16), closed: make(chan struct{})} }

func (e *echoSession) WritePacket(p []byte, to wire.Target) error {
	if e.silent {
		return nil
	}
	select {
	case e.ch <- pkt{append([]byte(nil), p...), to}:
		return nil
	case <-e.closed:
		return io.ErrClosedPipe
	}
}

func (e *echoSession) ReadPacket() ([]byte, wire.Target, error) {
	if e.refusing {
		return nil, wire.Target{}, io.EOF
	}
	select {
	case p := <-e.ch:
		return p.data, p.addr, nil
	case <-e.closed:
		return nil, wire.Target{}, io.EOF
	}
}

func (e *echoSession) Close() error {
	e.closeOnce.Do(func() { close(e.closed) })
	return nil
}

// udpBoard is a switchboard over paths a, b, c with a the leader, b second.
func udpBoard(t *testing.T) (*Switchboard, string, map[string]*fakeUDPWire) {
	t.Helper()
	s, err := New(DefaultConfig(), threeDead(t))
	if err != nil {
		t.Fatal(err)
	}
	s.probe = func(context.Context, []string) bool { return false }
	for i := 0; i < 6; i++ {
		s.observe(delivered("a"))
	}
	if l := leaderOf(s); l != "a" {
		t.Fatalf("leader %s, want a", l)
	}
	for i := 0; i < 3; i++ {
		s.observe(delivered("b"))
		s.observe(wireFailed("c"))
	}
	fakes := map[string]*fakeUDPWire{}
	for _, id := range []string{"a", "b", "c"} {
		fakes[id] = &fakeUDPWire{id: id, newSess: func() wire.PacketSession { return newEcho() }}
		s.wires[id] = fakes[id]
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.serveListener(ctx, ln) }()
	return s, ln.Addr().String(), fakes
}

// associate does what hev does: greeting, then UDP-in-TCP for 0.0.0.0:0.
func associate(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0, 5, socksFwdUDP, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 12)
	if _, err := io.ReadFull(c, rep); err != nil || rep[0] != 5 || rep[1] != 0 || rep[3] != 0 {
		t.Fatalf("handshake replies %v %v, want success", rep, err)
	}
	return c
}

func send(t *testing.T, c net.Conn, to string, data []byte) {
	t.Helper()
	if err := writeDatagram(c, netip.MustParseAddrPort(to), data); err != nil {
		t.Fatal(err)
	}
}

// Datagrams ride the leader; a path that cannot carry UDP is passed over at
// once; replies come back framed from their address; one too large for hev's
// buffer is dropped rather than sent to end hev's session.
func TestUDPAssociation(t *testing.T) {
	s, addr, fakes := udpBoard(t)
	fakes["a"].dialErr = errors.New("UDP not enabled")
	c := associate(t, addr)
	send(t, c, "1.1.1.1:53", []byte("ping"))
	d, err := readDatagram(c)
	if err != nil || d.to != (wire.Target{Host: "1.1.1.1", Port: 53}) || string(d.data) != "ping" {
		t.Fatalf("reply %+v %v", d, err)
	}
	if fakes["a"].dials.Load() != 1 || fakes["b"].dials.Load() != 1 || fakes["c"].dials.Load() != 0 {
		t.Fatalf("dials a=%d b=%d c=%d, want the leader tried, then b", fakes["a"].dials.Load(), fakes["b"].dials.Load(), fakes["c"].dials.Load())
	}
	send(t, c, "1.1.1.1:53", make([]byte, hevUDPBuf-7+1))
	send(t, c, "1.1.1.1:53", make([]byte, hevUDPBuf-7))
	if d, err = readDatagram(c); err != nil || len(d.data) != hevUDPBuf-7 {
		t.Fatalf("after an oversized reply got %d bytes (%v), want the largest hev takes", len(d.data), err)
	}
	if n := s.Status().UDP; n != 1 {
		t.Fatalf("status udp = %d, want 1", n)
	}
}

// UDP/443 (QUIC) and destinations that mean nothing at the exit end the
// association with no path dialled: apps fall back to TCP.
func TestUDPRefusesQUICAndUnroutable(t *testing.T) {
	s, addr, fakes := udpBoard(t)
	for _, to := range []string{"142.250.1.1:443", "10.0.0.1:53", "198.18.0.2:53"} {
		c := associate(t, addr)
		send(t, c, to, []byte("x"))
		if _, err := c.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("%s: read %v, want the association closed", to, err)
		}
	}
	for id, f := range fakes {
		if f.dials.Load() != 0 {
			t.Fatalf("path %s dialled for a refused datagram", id)
		}
	}
	if s.Status().UDP != 0 {
		t.Fatal("refused associations counted")
	}
}

// A path that ends an association at once, with no answer, refuses UDP: the
// next association starts elsewhere. An association the app side ends is no
// verdict on its path.
func TestUDPRefusingPathGoesBack(t *testing.T) {
	s, addr, fakes := udpBoard(t)
	fakes["a"].newSess = func() wire.PacketSession { e := newEcho(); e.refusing = true; return e }
	c := associate(t, addr)
	send(t, c, "1.1.1.1:53", []byte("q"))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("read %v, want the association over", err)
	}
	c = associate(t, addr)
	send(t, c, "1.1.1.1:53", []byte("q"))
	if d, err := readDatagram(c); err != nil || string(d.data) != "q" {
		t.Fatalf("second association: %+v %v", d, err)
	}
	if fakes["a"].dials.Load() != 1 || fakes["b"].dials.Load() != 1 {
		t.Fatalf("dials a=%d b=%d, want the refusing leader once, then b", fakes["a"].dials.Load(), fakes["b"].dials.Load())
	}

	fakes["b"].newSess = func() wire.PacketSession { e := newEcho(); e.silent = true; return e }
	c = associate(t, addr)
	send(t, c, "1.1.1.1:53", []byte("q"))
	time.Sleep(100 * time.Millisecond)
	c.Close()
	deadline := time.Now().Add(2 * time.Second)
	for s.active.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	s.mu.Lock()
	back := s.udpBack["b"]
	s.mu.Unlock()
	if back != 0 {
		t.Fatal("an association the app ended put its path at the back")
	}
}
