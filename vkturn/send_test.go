package vkturn

import (
	"encoding/binary"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"
)

// seqRecorder is a relay socket that keeps the RTP seq of every packet
// written to it, in wire order.
type seqRecorder struct {
	net.PacketConn
	mu   sync.Mutex
	seqs []uint16
}

func (r *seqRecorder) WriteTo(p []byte, _ net.Addr) (int, error) {
	r.mu.Lock()
	r.seqs = append(r.seqs, binary.BigEndian.Uint16(p[2:4]))
	r.mu.Unlock()
	return len(p), nil
}

// FV-012: keepalive and WriteTo send on one channel at once. Each packet must
// get its own seq, and the wire must carry them in order: an RTP stream
// with repeated or shuffled numbers does not look like a call.
func TestSendOnOneChannelFromManyGoroutines(t *testing.T) {
	s, err := NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	rec := &seqRecorder{}
	c := &relayConn{sealer: s, server: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1}}
	ch := &channel{relay: rec, st: NewStream(), pace: newPacer(1 << 40)}
	ch.lastRecv.Store(time.Now().UnixNano())
	const workers, each = 8, 500
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				c.send(ch, []byte("x"))
			}
		}()
	}
	wg.Wait()
	if len(rec.seqs) != workers*each {
		t.Fatalf("wrote %d packets, want %d", len(rec.seqs), workers*each)
	}
	for i := 1; i < len(rec.seqs); i++ {
		if rec.seqs[i] != rec.seqs[i-1]+1 {
			t.Fatalf("packet %d: seq %d after %d", i, rec.seqs[i], rec.seqs[i-1])
		}
	}
}

// failRelay is a relay socket whose sends fail, as a phone's do for a moment
// when it changes networks or a firewall drops them (sendto: EPERM).
type failRelay struct{ net.PacketConn }

func (failRelay) WriteTo(p []byte, _ net.Addr) (int, error) {
	return 0, &net.OpError{Op: "write", Net: "udp4", Err: syscall.EPERM}
}

// A failed send is a lost datagram, not the session's end: kcp keeps the first
// write error it sees and fails every later write with it, so a tunnel whose
// relays blinked for a second stayed dead for good while heal had already
// brought fresh channels up (measured from NSK 16.11: kilbond's VK leg never
// rejoined). The channel still counts the failures and is retired at deadAfter.
func TestFailedSendIsALossNotAnError(t *testing.T) {
	s, err := NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	c := &relayConn{sealer: s, server: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1}, done: make(chan struct{})}
	ch := &channel{relay: failRelay{}, st: NewStream(), pace: newPacer(1 << 40)}
	chans := []*channel{ch}
	c.chans.Store(&chans)
	for i := 0; i < deadAfter; i++ {
		if n, err := c.WriteTo([]byte("data"), nil); err != nil || n != 4 {
			t.Fatalf("send %d: n=%d err=%v, want 4 and nil", i, n, err)
		}
	}
	if !ch.dead.Load() {
		t.Fatal("a channel whose sends all failed is not retired")
	}
	close(c.done)
	if _, err := c.WriteTo([]byte("data"), nil); err == nil {
		t.Fatal("a closed conn takes writes")
	}
}
