package switchboard

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tsyrenov1987/farvater-core/wire"
)

// streamWire answers every flow with n bytes and keeps it open.
type streamWire struct {
	id string
	n  int
}

func (w *streamWire) ID() string                                 { return w.id }
func (w *streamWire) Spec() wire.PathSpec                        { return wire.PathSpec{ID: w.id} }
func (w *streamWire) NeedsHandshake() bool                       { return false }
func (w *streamWire) Close() error                               { return nil }
func (w *streamWire) Dial(context.Context) (wire.Session, error) { return streamSession{w.n}, nil }

type streamSession struct{ n int }

func (st streamSession) Run(ctx context.Context, _ wire.Target, _ []byte, _ <-chan []byte, down io.Writer, m wire.Meter) (wire.Outcome, error) {
	p := make([]byte, st.n)
	m.Down(p)
	if _, err := down.Write(p); err != nil {
		return wire.OutcomeError, err
	}
	<-ctx.Done()
	return wire.OutcomeCanceled, ctx.Err()
}
func (streamSession) Close() error { return nil }

func downBytes(s *Switchboard) (total int64, by map[string]int64) {
	by = map[string]int64{}
	for _, p := range s.Status().Paths {
		total += p.DownBytes
		by[p.ID] = p.DownBytes
	}
	return total, by
}

// The apps draw each path's live flow from Status: a flow's bytes count while
// it still runs, on the path carrying it, and so do UDP's.
func TestPathsCountBytesAsTheyFlow(t *testing.T) {
	s, addr, fakes := udpBoard(t)
	for _, id := range []string{"a", "b", "c"} {
		s.wires[id] = &streamWire{id: id, n: 70_000}
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	req := append([]byte{5, 1, 0, 5, 1, 0, 3, 11}, "example.com"...)
	if _, err := c.Write(append(req, 1, 187)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 2+10)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 70_000)); err != nil {
		t.Fatal(err)
	}
	total, by := downBytes(s)
	if total != 70_000 || s.Status().Active != 1 {
		t.Fatalf("while the flow runs: %d bytes down %v, %d active; want 70000 on one path", total, by, s.Status().Active)
	}

	for _, id := range []string{"a", "b", "c"} {
		s.wires[id] = fakes[id]
	}
	fakes["a"].dialErr = errors.New("UDP not enabled")
	u := associate(t, addr)
	send(t, u, "1.1.1.1:53", []byte("ping"))
	if _, err := readDatagram(u); err != nil {
		t.Fatal(err)
	}
	for _, p := range s.Status().Paths {
		if p.ID == "b" && (p.UpBytes != 4 || p.DownBytes != 4+by["b"]) {
			t.Fatalf("UDP over b: up %d down %d, want 4 more each way", p.UpBytes, p.DownBytes)
		}
	}
}
