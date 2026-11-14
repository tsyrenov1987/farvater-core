package wire

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestKilvaterLiveLab drives one transfer through a kilvater entry with the
// client's real dialer (uTLS profile, HTTP/2 profile, warm-up), for a capture
// taken on the server: KILLIVE_URI is the share link, KILLIVE_TARGET the
// host:port the server is to reach, KILLIVE_UP the number of bytes to send (0:
// download until the target closes).
func TestKilvaterLiveLab(t *testing.T) {
	uri := os.Getenv("KILLIVE_URI")
	if uri == "" {
		t.Skip("needs a live entry: KILLIVE_URI")
	}
	spec, err := ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	host, p, err := net.SplitHostPort(os.Getenv("KILLIVE_TARGET"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(p)
	upBytes, _ := strconv.Atoi(os.Getenv("KILLIVE_UP"))
	if os.Getenv("KILLIVE_NORESUME") == "1" {
		KilvaterResume = false
		defer func() { KilvaterResume = true }()
	}
	w, err := newKilvater(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	sess, err := w.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	up := make(chan []byte)
	cw := &countW{}
	if upBytes == 0 {
		if _, err := sess.Run(ctx, Target{Host: host, Port: port}, []byte("x"), up, cw, nopMeter{}); err != nil {
			t.Logf("download ended: %v", err)
		}
		t.Logf("down %d bytes in %v", cw.n, time.Since(start).Round(time.Millisecond))
		return
	}
	// KILLIVE_ACK=1: the target (peers.py port 19084) is told the length first
	// and answers once it has it all, so the time is the upload's own, not the
	// 2 s a flow whose app has finished gives the far side.
	ack := os.Getenv("KILLIVE_ACK") == "1"
	var prelude []byte
	if ack {
		prelude = binary.BigEndian.AppendUint64(nil, uint64(upBytes))
	}
	acked := make(chan time.Duration, 1)
	done := make(chan struct{})
	go func() {
		sess.Run(ctx, Target{Host: host, Port: port}, prelude, up, &firstByte{start: start, at: acked}, nopMeter{})
		close(done)
	}()
	// The app's writes as a TLS stack hands them down: 16 KiB at a time.
	buf := make([]byte, 16<<10)
	for n := 0; n < upBytes; n += len(buf) {
		up <- append([]byte(nil), buf[:min(len(buf), upBytes-n)]...)
	}
	if ack {
		select {
		case d := <-acked:
			t.Logf("up %d bytes in %v (acked by target)", upBytes, d.Round(time.Millisecond))
		case <-done:
			t.Fatal("flow ended before the target acked")
		}
		close(up)
		<-done
		return
	}
	close(up)
	<-done
	t.Logf("up %d bytes in %v", upBytes, time.Since(start).Round(time.Millisecond))
}

// firstByte reports, once, how long after start the first byte came down.
type firstByte struct {
	start time.Time
	at    chan time.Duration
	once  sync.Once
}

func (f *firstByte) Write(p []byte) (int, error) {
	if len(p) > 0 {
		f.once.Do(func() { f.at <- time.Since(f.start) })
	}
	return len(p), nil
}
