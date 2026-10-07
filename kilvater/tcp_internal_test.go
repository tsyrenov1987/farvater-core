package kilvater

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// TestTCPReturnsWhenStreamEnds: once the stream's context ends, tcp must stop
// reading the remote and return, even when the remote never sends or closes.
// Before the context watcher closed the remote, the downstream reader blocked
// on remote.Read forever and the handler goroutine leaked.
func TestTCPReturnsWhenStreamEnds(t *testing.T) {
	// A target that accepts and then stays silent: it never reads, writes, or closes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- c
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	upR, upW := io.Pipe()
	done := make(chan struct{})
	srv := &Server{}
	go func() {
		srv.tcp(ctx, ln.Addr().String(), upR, io.Discard)
		close(done)
	}()

	// Wait for the server to dial the silent target.
	var tc net.Conn
	select {
	case tc = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("server never dialed the target")
	}
	defer tc.Close()

	// Send one DATA frame; the target is silent, so the downstream reader now
	// blocks on remote.Read with nothing to read.
	if err := WriteFrame(upW, FrameData, []byte("hi")); err != nil {
		t.Fatal(err)
	}

	// The stream goes away: context ends and the upstream breaks.
	cancel()
	upW.CloseWithError(io.ErrClosedPipe)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("tcp did not return after the stream ended: the remote read leaked")
	}
}
