package vkturn

import (
	"encoding/binary"
	"net"
	"sync"
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
