package wire

import (
	"context"
	"io"
	"net"
	"os"
	"strconv"
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
	done := make(chan struct{})
	go func() {
		sess.Run(ctx, Target{Host: host, Port: port}, nil, up, io.Discard, nopMeter{})
		close(done)
	}()
	// The app's writes as a TLS stack hands them down: 16 KiB at a time.
	buf := make([]byte, 16<<10)
	for n := 0; n < upBytes; n += len(buf) {
		up <- append([]byte(nil), buf[:min(len(buf), upBytes-n)]...)
	}
	close(up)
	<-done
	t.Logf("up %d bytes in %v", upBytes, time.Since(start).Round(time.Millisecond))
}
