package wire

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"
)

// recConn notes the length of every TLS record that crosses it.
type recConn struct {
	net.Conn
	mu      sync.Mutex
	in, out recParse
}

type recParse struct {
	hdr  []byte
	left int
	typ  byte
	recs []int
}

func (p *recParse) feed(b []byte) {
	for len(b) > 0 {
		if p.left > 0 {
			n := min(p.left, len(b))
			p.left -= n
			b = b[n:]
			continue
		}
		n := min(5-len(p.hdr), len(b))
		p.hdr = append(p.hdr, b[:n]...)
		b = b[n:]
		if len(p.hdr) == 5 {
			p.left = int(p.hdr[3])<<8 | int(p.hdr[4])
			if p.hdr[0] == 23 {
				p.recs = append(p.recs, p.left)
			}
			p.hdr = p.hdr[:0]
		}
	}
}

func (c *recConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	c.in.feed(b[:n])
	c.mu.Unlock()
	return n, err
}

func (c *recConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.mu.Lock()
	c.out.feed(b[:n])
	c.mu.Unlock()
	return n, err
}

type recLog struct {
	mu    sync.Mutex
	conns []*recConn
}

func (l *recLog) dial(addr string) (*recConn, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	rc := &recConn{Conn: c}
	l.mu.Lock()
	l.conns = append(l.conns, rc)
	l.mu.Unlock()
	return rc, nil
}

func (l *recLog) take() (in, out []int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.conns {
		c.mu.Lock()
		in = append(in, c.in.recs...)
		out = append(out, c.out.recs...)
		c.in.recs, c.out.recs = nil, nil
		c.mu.Unlock()
	}
	return
}

func recStats(name string, r []int) string {
	if len(r) == 0 {
		return name + ": none"
	}
	s := append([]int(nil), r...)
	sort.Ints(s)
	total, small, distinct := 0, 0, map[int]int{}
	for _, v := range s {
		total += v
		if v < 1000 {
			small++
		}
		distinct[v]++
	}
	top, topN := 0, 0
	for v, n := range distinct {
		if n > topN {
			top, topN = v, n
		}
	}
	pct := func(p int) int { return s[len(s)*p/100] }
	return fmt.Sprintf("%-22s n=%-5d bytes=%-9d p10=%-5d p50=%-5d p90=%-5d max=%-5d <1000:%4.1f%%  most common %d: %4.1f%%  distinct=%d",
		name, len(s), total, pct(10), pct(50), pct(90), s[len(s)-1], 100*float64(small)/float64(len(s)), top, 100*float64(topN)/float64(len(s)), len(distinct))
}

// TestKilvaterWireLab measures what an observer of the TLS connection sees:
// the lengths of the records of a download of the decoy's own file, and of
// the same amount of data through the tunnel, against a kilvaterd behind
// nginx. tools/kv-wirelab.sh sets the stand up and runs it.
func TestKilvaterWireLab(t *testing.T) {
	addr := os.Getenv("KILLAB_ADDR")
	if addr == "" {
		t.Skip("needs the stand: tools/kv-wirelab.sh")
	}
	const size = 8 << 20
	src, _ := net.Listen("tcp", "127.0.0.1:18080")
	sink, _ := net.Listen("tcp", "127.0.0.1:18081")
	defer src.Close()
	defer sink.Close()
	go func() {
		for {
			c, err := src.Accept()
			if err != nil {
				return
			}
			go func() {
				c.Read(make([]byte, 1)) // the prelude, so Close is a FIN
				buf := make([]byte, 64<<10)
				for n := 0; n < size; n += len(buf) {
					c.Write(buf)
				}
				c.Close()
			}()
		}
	}()
	sunk := make(chan int64, 4)
	go func() {
		for {
			c, err := sink.Accept()
			if err != nil {
				return
			}
			go func() {
				n, _ := io.Copy(io.Discard, c)
				c.Close()
				sunk <- n
			}()
		}
	}()
	port := func(l net.Listener) int {
		_, p, _ := net.SplitHostPort(l.Addr().String())
		n, _ := strconv.Atoi(p)
		return n
	}

	log := &recLog{}
	tlsDial := func(ctx context.Context) (net.Conn, error) {
		rc, err := log.dial(addr)
		if err != nil {
			return nil, err
		}
		tc := tls.Client(rc, &tls.Config{InsecureSkipVerify: true, ServerName: "lab.test", NextProtos: []string{"h2"}})
		if err := tc.HandshakeContext(ctx); err != nil {
			rc.Close()
			return nil, err
		}
		return tc, nil
	}

	// The decoy's own file, the way any visitor gets it.
	hc := &http.Client{Transport: &http.Transport{ForceAttemptHTTP2: true,
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return tlsDial(ctx) }}}
	resp, err := hc.Get("https://lab.test/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	n, _ := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	hc.CloseIdleConnections()
	in, out := log.take()
	t.Logf("static GET %d bytes, proto %s", n, resp.Proto)
	t.Log(recStats("static down", in))
	t.Log(recStats("  (its upstream)", out))
	t.Logf("static down, records 300..340: %v", in[300:340])
	static := in
	for i := 0; i < 3; i++ {
		resp, err := hc.Get("https://lab.test/big.bin")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		hc.CloseIdleConnections()
		again, _ := log.take()
		t.Logf("distance of another static download to the first: %.3f", recDistance(static, again))
	}

	spec := kilTestSpec(os.Getenv("KILLAB_KEY"))
	spec.Fingerprint = ""
	spec.Pad = os.Getenv("KILLAB_PAD")
	w, err := newKilWire(spec, tlsDial)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sess, err := w.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	log.take() // handshake and warm-up are not the transfer
	up := make(chan []byte)
	cw := &countW{}
	defer func() { t.Logf("downloaded through the tunnel: %d bytes", cw.n) }()
	if _, err := sess.Run(ctx, Target{Host: "127.0.0.1", Port: port(src)}, []byte("x"), up, cw, nopMeter{}); err != nil {
		t.Logf("download ended: %v", err)
	}
	in, out = log.take()
	t.Log(recStats("tunnel bulk down", in))
	t.Logf("tunnel down, records 300..340: %v", in[300:340])
	t.Logf("distance of tunnel down to static down (0 same, 1 nothing in common): %.3f", recDistance(static, in))
	t.Log(recStats("  (its upstream)", out))

	sess, err = w.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	log.take()
	up = make(chan []byte)
	done := make(chan struct{})
	go func() {
		sess.Run(ctx, Target{Host: "127.0.0.1", Port: port(sink)}, nil, up, io.Discard, nopMeter{})
		close(done)
	}()
	buf := make([]byte, 32<<10)
	for n := 0; n < size; n += len(buf) {
		up <- append([]byte(nil), buf...)
	}
	close(up)
	select {
	case got := <-sunk:
		t.Logf("sink got %d bytes", got)
	case <-time.After(20 * time.Second):
		t.Log("sink never saw the end")
	}
	<-done
	in, out = log.take()
	t.Log(recStats("tunnel bulk up", out))
	t.Log(recStats("  (its downstream)", in))
}

type countW struct{ n int }

func (c *countW) Write(b []byte) (int, error) { c.n += len(b); return len(b), nil }

// recDistance is the total variation distance between two sets of record
// lengths, over buckets 128 bytes wide.
func recDistance(a, b []int) float64 {
	ha, hb := map[int]float64{}, map[int]float64{}
	for _, v := range a {
		ha[v/128] += 1 / float64(len(a))
	}
	for _, v := range b {
		hb[v/128] += 1 / float64(len(b))
	}
	d := 0.0
	for k, v := range ha {
		if w := hb[k]; v > w {
			d += v - w
		}
	}
	return d
}
