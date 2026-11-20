package wire

import (
	"testing"
	"time"
)

// A connection that died in silence while nothing rode it: the stream that
// takes it next is let go within the probe's wait, not left to hang, and the
// one after dials afresh.
func TestH2MuxProbesAConnectionReusedAfterQuiet(t *testing.T) {
	d := &freezeDialer{}
	m := newH2Mux(d.dial, 0, 0)
	m.probeIdle = 50 * time.Millisecond
	defer m.Close()

	a := openOrFail(t, m)
	echo(t, a, "first")
	a.Close()
	d.freeze()
	time.Sleep(60 * time.Millisecond)

	stuck := openOrFail(t, m)
	start := time.Now()
	released := make(chan struct{})
	go func() {
		stuck.Read(make([]byte, 1))
		close(released)
	}()
	select {
	case <-released:
	case <-time.After(probePing + 2*time.Second):
		t.Fatal("the stream on the dead connection still hangs")
	}
	t.Logf("the stream on the dead connection ended after %v", time.Since(start).Round(time.Millisecond))
	stuck.Close()

	b := openOrFail(t, m)
	if !answers(b, "fresh", 2*time.Second) {
		t.Fatal("the stream after the probe did not get through")
	}
	b.Close()
	if got := d.count(); got != 2 {
		t.Fatalf("%d dials, want the dead connection and a fresh one", got)
	}
}

// A live connection reused after quiet answers the probe and stays.
func TestH2MuxProbeLeavesALiveConnection(t *testing.T) {
	d := &freezeDialer{}
	m := newH2Mux(d.dial, 0, 0)
	m.probeIdle = 50 * time.Millisecond
	defer m.Close()

	a := openOrFail(t, m)
	echo(t, a, "first")
	a.Close()
	time.Sleep(60 * time.Millisecond)
	b := openOrFail(t, m)
	echo(t, b, "second")
	time.Sleep(200 * time.Millisecond)
	echo(t, b, "third")
	b.Close()
	if got := d.count(); got != 1 {
		t.Fatalf("%d dials, want the one live connection kept", got)
	}
}
