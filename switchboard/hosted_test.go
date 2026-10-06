package switchboard

import (
	"context"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/catalogue"
	"github.com/tsyrenov1987/farvater-core/wire"
)

const olcLink = "olcrtc://wbstream?vp8channel@room-1#d823fa01cb3e0609b67322f7cf984c4ee2e4ce2e294936fc24ef38c9e59f4799$o"

func hostedBoard(t *testing.T, hosted []wire.Kind, links ...string) *Switchboard {
	t.Helper()
	cat, err := catalogue.Parse([]byte(strings.Join(links, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Hosted = hosted
	s, err := New(cfg, cat)
	if err != nil {
		t.Fatal(err)
	}
	s.probe = func(context.Context, []string) bool { return false }
	return s
}

const deadLink = "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:9?security=tls&sni=example.com&type=tcp#a"

var runOlc = []wire.Kind{wire.KindOlcRTC}

// An app that does not run olcRTC gets its paths skipped; one that does gets
// them asleep until it hands over their doors.
func TestHostedPathsOnlyWhereTheAppRunsThem(t *testing.T) {
	s := hostedBoard(t, nil, deadLink, olcLink)
	if p := s.Paths(); !slices.Equal(p, []string{"a"}) || len(s.Skipped) != 1 || !strings.HasPrefix(s.Skipped[0], "o: ") || len(s.Hosted()) != 0 {
		t.Fatalf("not run by the app: paths %v, skipped %v, hosted %v", p, s.Skipped, s.Hosted())
	}
	s = hostedBoard(t, runOlc, deadLink, olcLink)
	h := s.Hosted()
	if p := s.Paths(); !slices.Equal(p, []string{"a", "o"}) || len(h) != 1 {
		t.Fatalf("run by the app: paths %v, hosted %+v", p, h)
	}
	want := HostedPath{ID: "o", Kind: "olcrtc", Provider: "wbstream", Transport: "vp8channel", Room: "room-1", Key: "d823fa01cb3e0609b67322f7cf984c4ee2e4ce2e294936fc24ef38c9e59f4799"}
	if h[0] != want {
		t.Fatalf("hosted %+v, want %+v", h[0], want)
	}
	if st := s.Status(); !st.Paths[1].Asleep || st.Paths[0].Asleep || st.Paths[1].Server != "wbstream" {
		t.Fatalf("status %+v", st.Paths)
	}
}

// The call is wanted only on need: in a restricted network, while it leads,
// or with nothing else in the catalogue; then for the linger after.
func TestHostedWantedOnNeed(t *testing.T) {
	s := hostedBoard(t, runOlc, deadLink, olcLink)
	want := func() bool { t.Helper(); return s.Hosted()[0].Want }
	if want() {
		t.Fatal("wanted with an ordinary path in the catalogue and no need")
	}
	s.mu.Lock()
	s.b.EnterRestricted(nowMs())
	s.mu.Unlock()
	if !want() {
		t.Fatal("not wanted in a restricted network")
	}
	s.SetNetwork("wifi:1")
	time.Sleep(5 * time.Millisecond)
	if s.b.Restricted() || !want() || s.wantTill["o"]-nowMs() < 9*60_000 {
		t.Fatal("restriction over: should still be wanted for the ten minutes after")
	}
	s.wantTill["o"] = nowMs() - 1
	if want() {
		t.Fatal("still wanted after the linger")
	}

	// Up and delivering, it takes the lead and is wanted for leading.
	if err := s.SetEndpoint("o", wire.Endpoint{Addr: "127.0.0.1:9"}); err != nil || s.b.Asleep("o") {
		t.Fatalf("door handed over: %v, asleep %v", err, s.b.Asleep("o"))
	}
	for i := 0; i < 8; i++ {
		s.observe(delivered("o"))
		s.observe(wireFailed("a"))
	}
	if l := leaderOf(s); l != "o" || !want() {
		t.Fatalf("leader %q, wanted %v", l, s.Hosted()[0].Want)
	}
	if err := s.SetEndpoint("a", wire.Endpoint{Addr: "127.0.0.1:9"}); err == nil {
		t.Fatal("a door for a path the app does not host")
	}

	only := hostedBoard(t, runOlc, olcLink)
	if !only.Hosted()[0].Want {
		t.Fatal("the only path is not wanted")
	}
}

// fixedDoor is the app's door stand-in: any CONNECT goes to the echo at to.
func fixedDoor(t *testing.T, to string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 3+2+1+2+1+1) // greeting, choice skipped; auth u/p of one byte each
				if _, err := io.ReadFull(c, b[:3]); err != nil {
					return
				}
				_, _ = c.Write([]byte{5, 2})
				if _, err := io.ReadFull(c, b[:5]); err != nil {
					return
				}
				_, _ = c.Write([]byte{1, 0})
				h := make([]byte, 5)
				if _, err := io.ReadFull(c, h); err != nil {
					return
				}
				if _, err := io.ReadFull(c, make([]byte, int(h[4])+2)); err != nil {
					return
				}
				out, err := net.Dial("tcp", to)
				if err != nil {
					return
				}
				defer out.Close()
				_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go func() { _, _ = io.Copy(out, c) }()
				_, _ = io.Copy(c, out)
			}()
		}
	}()
	return ln.Addr().String()
}

// With its door handed over a hosted path carries flows; before that, and
// once the door is taken back, a flow gets nothing and leaves no receipt.
func TestHostedPathCarriesFlowsOnlyWhileUp(t *testing.T) {
	s := hostedBoard(t, runOlc, olcLink)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.serveListener(ctx, ln) }()

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()

	ping := func() bool {
		t.Helper()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Write([]byte{5, 1, 0})
		_, _ = io.ReadFull(c, make([]byte, 2))
		_, _ = c.Write(append(append([]byte{5, 1, 0, 3, 9}, "echo.test"...), 0, 7))
		_, _ = io.ReadFull(c, make([]byte, 10))
		_, _ = c.Write([]byte("ping"))
		got := make([]byte, 4)
		_, err = io.ReadFull(c, got)
		return err == nil && string(got) == "ping"
	}
	if ping() || len(s.Receipts()) != 0 {
		t.Fatalf("asleep, yet carried or recorded: %d receipts", len(s.Receipts()))
	}
	if err := s.SetEndpoint("o", wire.Endpoint{Addr: fixedDoor(t, echo.Addr().String()), User: "u", Pass: "p"}); err != nil {
		t.Fatal(err)
	}
	if !ping() {
		t.Fatal("up, yet the flow did not come back")
	}
	if err := s.SetEndpoint("o", wire.Endpoint{}); err != nil || !s.Status().Paths[0].Asleep {
		t.Fatalf("door taken back: %v, status %+v", err, s.Status().Paths[0])
	}
	n := len(s.Receipts())
	if ping() || len(s.Receipts()) != n {
		t.Fatal("asleep again, yet carried or recorded")
	}
}
