package wire

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/net/http2"

	"github.com/tsyrenov1987/farvater-core/kilvater"
)

// splitOnly lets through what a CDN with no POST and no streamed request
// bodies would: GET, HEAD and OPTIONS, nothing with a body. It counts the
// requests so a test can see the uplink went up in pieces.
type splitOnly struct {
	h     http.Handler
	allow string // the extra method the CDN passes ("" none)
	n     atomic.Int64
}

func (s *splitOnly) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.n.Add(1)
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != s.allow {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.h.ServeHTTP(w, r)
}

func splitDial(t *testing.T, h http.Handler) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		c, s := net.Pipe()
		t.Cleanup(func() { s.Close() })
		go (&http2.Server{}).ServeConn(s, &http2.ServeConnOpts{Handler: h})
		return c, nil
	}
}

func TestKilvaterSplitFlow(t *testing.T) {
	for _, mode := range []string{"split", "split-post"} {
		t.Run(mode, func(t *testing.T) {
			key, hexKey := kilTestKey(t)
			edge := &splitOnly{h: kilServerFor(key)}
			if mode == "split-post" {
				edge.allow = http.MethodPost
			}
			spec := kilTestSpec(hexKey)
			spec.Mode = mode
			w, err := newKilWire(spec, splitDial(t, edge))
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			// The flow ends as a plain kilvater flow does (canceled, ~2 s on this
			// test's clocks): finish fails the test if it does not end at all.
			flowEchoOver(t, w)()
			if edge.n.Load() < 3 {
				t.Fatalf("%d requests: the uplink did not go up as pieces", edge.n.Load())
			}
		})
	}
}

// A plain kilvater stream (a streamed POST) does not get through the same
// edge: this is the case split mode is for.
func TestKilvaterStreamBlockedBySplitEdge(t *testing.T) {
	key, hexKey := kilTestKey(t)
	w, err := newKilWire(kilTestSpec(hexKey), splitDial(t, &splitOnly{h: kilServerFor(key)}))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	s, err := w.Dial(context.Background())
	if err == nil {
		_, err = s.Run(context.Background(), Target{Host: "127.0.0.1", Port: 9}, nil, make(chan []byte), io.Discard, nopMeter{})
	}
	if err == nil {
		t.Fatal("a streamed POST went through an edge that refuses POST")
	}
}

func TestKilvaterSplitV2Flow(t *testing.T) {
	var master kilvater.Key
	rand.Read(master[:])
	id := kilvater.KeyIDFor(master, []byte("split"))
	k := kilvater.DeriveKey(master, id)
	spec := kilTestSpec(hex.EncodeToString(k[:]))
	spec.KeyID = id.String()
	spec.Mode = "split"
	srv := &kilvater.Server{
		Verifier: kilvater.NewVerifierConfig(kilvater.VerifierConfig{Master: &master}),
		Decoy:    http.HandlerFunc(kilDecoy), AllowPrivate: true}
	w, err := newKilWire(spec, splitDial(t, &splitOnly{h: srv}))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	flowEchoOver(t, w)
}

func TestKilvaterSplitModeParsed(t *testing.T) {
	_, hexKey := kilTestKey(t)
	s, err := ParseURI("kilvater://" + hexKey + "@kv.test:443/connect?mode=split#x")
	if err != nil || s.Mode != "split" {
		t.Fatalf("mode=split: %q %v", s.Mode, err)
	}
	if _, err := ParseURI("kilvater://" + hexKey + "@kv.test:443/connect?mode=packet-up#x"); err == nil ||
		!strings.Contains(err.Error(), "unknown mode") {
		t.Fatalf("an unknown mode passed: %v", err)
	}
}
