package wire

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/tsyrenov1987/farvater-core/kilvater"
)

// bondOver builds a bond whose legs all reach one in-process server; a nil
// entry in dead makes that leg's dial fail.
func bondOver(t *testing.T, legs int, dead map[int]bool) *bondWire {
	t.Helper()
	key, hexKey := kilTestKey(t)
	srv := kilServerFor(key)
	var ws []*kilWire
	for i := 0; i < legs; i++ {
		i := i
		w, err := newKilWire(kilTestSpec(hexKey), func(ctx context.Context) (net.Conn, error) {
			if dead[i] {
				return nil, errors.New("leg down")
			}
			c, s := net.Pipe()
			t.Cleanup(func() { s.Close() })
			go (&http2.Server{}).ServeConn(s, &http2.ServeConnOpts{Handler: srv})
			return c, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		ws = append(ws, w)
	}
	bw := &bondWire{spec: PathSpec{ID: "bond", Kind: KindBond}, legs: ws}
	t.Cleanup(func() { bw.Close() })
	return bw
}

func TestBondFlow(t *testing.T) {
	flowEchoOver(t, bondOver(t, 2, nil))
}

// One leg that never opens does not stop the flow.
func TestBondFlowDeadLeg(t *testing.T) {
	flowEchoOver(t, bondOver(t, 3, map[int]bool{0: true}))
}

// A few megabytes cross the bond and come back from the echo intact.
func TestBondBulk(t *testing.T) {
	w := bondOver(t, 3, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sess, err := w.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port := echoTCP(t)
	data := make([]byte, 3<<20)
	rand.Read(data)
	up := make(chan []byte, 4)
	pr, pw := io.Pipe()
	go func() {
		sess.Run(ctx, Target{Host: "127.0.0.1", Port: port}, nil, up, pw, nopMeter{})
		pw.Close()
	}()
	go func() {
		for off := 0; off < len(data); off += 32 << 10 {
			end := off + 32<<10
			if end > len(data) {
				end = len(data)
			}
			up <- data[off:end]
		}
	}()
	got := make([]byte, len(data))
	if _, err := io.ReadFull(pr, got); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("echo came back wrong (%v)", err)
	}
	close(up)
}

// A server whose kilvater does not know JOIN closes the leg unanswered; with
// every leg like that the path is dead, not the flow.
func TestBondOldServer(t *testing.T) {
	key, hexKey := kilTestKey(t)
	srv := kilServerFor(key)
	old := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			rw.WriteHeader(200)
			rw.(http.Flusher).Flush()
			kilvater.ReadFrame(r.Body, nil) // the JOIN: not understood, the stream ends
			return
		}
		srv.ServeHTTP(rw, r)
	})
	var ws []*kilWire
	for i := 0; i < 2; i++ {
		w, err := newKilWire(kilTestSpec(hexKey), func(ctx context.Context) (net.Conn, error) {
			c, s := net.Pipe()
			t.Cleanup(func() { s.Close() })
			go (&http2.Server{}).ServeConn(s, &http2.ServeConnOpts{Handler: old})
			return c, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		ws = append(ws, w)
	}
	bw := &bondWire{spec: PathSpec{ID: "bond", Kind: KindBond}, legs: ws}
	defer bw.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := bw.Dial(ctx)
	if err != nil {
		t.Skipf("the old server refused the stream outright: %v", err)
	}
	up := make(chan []byte)
	o, err := sess.Run(ctx, Target{Host: "127.0.0.1", Port: echoTCP(t)}, []byte("hi"), up, io.Discard, nopMeter{})
	if !errors.Is(err, ErrWireDead) {
		t.Fatalf("outcome %v, %v; want ErrWireDead", o, err)
	}
}

func TestBondParse(t *testing.T) {
	leg := func(host string) string {
		return base64.RawURLEncoding.EncodeToString([]byte("kilvater://" + testOlcKey + "@" + host + ":443/connect?sni=" + host + "#l"))
	}
	spec, err := ParseURI("kilbond://x?leg=" + leg("a.test") + "&leg=" + leg("b.test") + "#bond%20one")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Kind != KindBond || len(spec.Legs) != 2 || spec.ID != "bond one" || spec.Host != "a.test" || spec.Legs[1].Host != "b.test" {
		t.Fatalf("%+v", spec)
	}
	if _, err := ParseURI("kilbond://x?leg=" + leg("a.test")); err == nil {
		t.Fatal("one leg parsed")
	}
	trojan := base64.RawURLEncoding.EncodeToString([]byte("trojan://pw@a.test:443#t"))
	if _, err := ParseURI("kilbond://x?leg=" + leg("a.test") + "&leg=" + trojan); err == nil {
		t.Fatal("a trojan leg parsed")
	}
}
