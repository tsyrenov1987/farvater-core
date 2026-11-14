package kilvater

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// resumeTarget accepts one connection and hands it to the test.
func resumeTarget(t *testing.T) (addr string, conn func() net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			ch <- c
		}
	}()
	return ln.Addr().String(), func() net.Conn {
		select {
		case c := <-ch:
			t.Cleanup(func() { c.Close() })
			return c
		case <-time.After(2 * time.Second):
			t.Fatal("the server never dialed the target")
			return nil
		}
	}
}

// testStream is one tunnel stream as the server sees it, with the test
// holding the client's ends. The server's frames are read as they come (its
// writes must not wait on the test) and queued, PAD left out.
type testStream struct {
	upW    *io.PipeWriter
	downR  *io.PipeReader
	frames chan testFrame
	done   chan struct{}
}

type testFrame struct {
	typ  byte
	body []byte
}

func (st *testStream) kill() {
	st.upW.CloseWithError(io.ErrClosedPipe)
	st.downR.CloseWithError(io.ErrClosedPipe)
	<-st.done
}

// next returns the next frame that is not PAD.
func (st *testStream) next(t *testing.T) (byte, []byte) {
	t.Helper()
	select {
	case f, ok := <-st.frames:
		if !ok {
			t.Fatal("the stream ended")
		}
		return f.typ, f.body
	case <-time.After(2 * time.Second):
		t.Fatal("no frame from the server")
	}
	return 0, nil
}

func openStream(run func(up io.Reader, down io.Writer)) *testStream {
	upR, upW := io.Pipe()
	downR, downW := io.Pipe()
	st := &testStream{upW: upW, downR: downR, frames: make(chan testFrame, 4096), done: make(chan struct{})}
	go func() {
		defer close(st.frames)
		for {
			typ, body, err := ReadFrame(downR, nil)
			if err != nil {
				return
			}
			if typ != FramePad {
				st.frames <- testFrame{typ, append([]byte(nil), body...)}
			}
		}
	}()
	go func() {
		run(upR, downW)
		downW.Close()
		close(st.done)
	}()
	return st
}

func targetClosed(c net.Conn, within time.Duration) bool {
	c.SetReadDeadline(time.Now().Add(within))
	_, err := c.Read(make([]byte, 1))
	ne, timeout := err.(net.Error)
	return err != nil && !(timeout && ne.Timeout())
}

var testSID = SessionID{1, 2, 3}

// A stream that is lost leaves the flow waiting; a new stream that names the
// session gets the bytes the client lacked, and the server says how many of
// the client's it has. Left alone past the grace, the target is closed.
func TestSessionResumeAndGrace(t *testing.T) {
	addr, conn := resumeTarget(t)
	srv := &Server{AllowPrivate: true, ResumeGrace: 300 * time.Millisecond}
	key := sessKey{"k", testSID}

	a := openStream(func(up io.Reader, down io.Writer) {
		srv.tcpSession(context.Background(), addr, key, up, down, nil)
	})
	if typ, body := a.next(t); typ != FrameFlowAck || !bytes.Equal(body, AckBody(0)) {
		t.Fatalf("first frame %d %x, want ACK 0", typ, body)
	}
	tc := conn()
	if typ, _ := a.next(t); typ != FrameFlowAck {
		t.Fatalf("frame %d after the dial, want ACK", typ)
	}
	WriteFrame(a.upW, FrameData, []byte("up-1"))
	got := make([]byte, 4)
	if _, err := io.ReadFull(tc, got); err != nil || string(got) != "up-1" {
		t.Fatalf("target got %q (%v)", got, err)
	}
	tc.Write([]byte("down-1"))
	if typ, body := a.next(t); typ != FrameData || string(body) != "down-1" {
		t.Fatalf("frame %d %q, want DATA down-1", typ, body)
	}

	a.kill()
	tc.Write([]byte("while away"))
	if targetClosed(tc, 100*time.Millisecond) {
		t.Fatal("the target was closed as soon as the stream was lost")
	}

	// The client took 4 of the 6 bytes before the cut.
	b := openStream(func(up io.Reader, down io.Writer) {
		srv.resume(AppendResume(nil, testSID, 4)[1:], "k", up, down, nil)
	})
	if typ, body := b.next(t); typ != FrameFlowAck || !bytes.Equal(body, AckBody(4)) {
		t.Fatalf("resumed stream opens with %d %x, want ACK 4", typ, body)
	}
	var back []byte
	for len(back) < len("-1while away") {
		typ, body := b.next(t)
		if typ != FrameData {
			t.Fatalf("frame %d, want DATA", typ)
		}
		back = append(back, body...)
	}
	if string(back) != "-1while away" {
		t.Fatalf("resumed from the wrong place: %q", back)
	}
	if rs := srv.ResumeStats(); rs.Resumed != 1 {
		t.Fatalf("stats %+v, want one resumed", rs)
	}

	// Another key cannot take the session over.
	c := openStream(func(up io.Reader, down io.Writer) {
		srv.resume(AppendResume(nil, testSID, 4)[1:], "other", up, down, nil)
	})
	if typ, body := c.next(t); typ != FrameClose || len(body) != 1 || body[0] != CloseGone {
		t.Fatalf("a stranger's resume got %d %x, want CLOSE gone", typ, body)
	}
	<-c.done

	b.kill()
	if !targetClosed(tc, 2*time.Second) {
		t.Fatal("the target stayed open after the grace ran out")
	}
	if rs := srv.ResumeStats(); rs.Kept != 0 || rs.HeldBytes != 0 || rs.Lost != 1 {
		t.Fatalf("stats after the grace %+v, want nothing kept and one lost", rs)
	}
	d := openStream(func(up io.Reader, down io.Writer) {
		srv.resume(AppendResume(nil, testSID, 16)[1:], "k", up, down, nil)
	})
	if typ, _ := d.next(t); typ != FrameClose {
		t.Fatalf("resume of a dropped session got %d, want CLOSE", typ)
	}
}

// END from the client closes the target at once: nothing waits out the grace.
func TestSessionEndClosesAtOnce(t *testing.T) {
	addr, conn := resumeTarget(t)
	srv := &Server{AllowPrivate: true, ResumeGrace: time.Minute}
	a := openStream(func(up io.Reader, down io.Writer) {
		srv.tcpSession(context.Background(), addr, sessKey{"k", testSID}, up, down, nil)
	})
	tc := conn()
	WriteFrame(a.upW, FrameEnd, nil)
	if !targetClosed(tc, 2*time.Second) {
		t.Fatal("the target stayed open after END")
	}
	select {
	case <-a.done:
	case <-time.After(2 * time.Second):
		t.Fatal("the stream's handler did not return after END")
	}
}

// A stream that has been replaced can no longer write to the target, even if
// its frames arrive late.
func TestSessionStaleStreamCannotWrite(t *testing.T) {
	addr, conn := resumeTarget(t)
	srv := &Server{AllowPrivate: true, ResumeGrace: time.Minute}
	a := openStream(func(up io.Reader, down io.Writer) {
		srv.tcpSession(context.Background(), addr, sessKey{"k", testSID}, up, down, nil)
	})
	tc := conn()
	// The second ACK is the session's own: only then is there one to resume.
	a.next(t)
	if typ, _ := a.next(t); typ != FrameFlowAck {
		t.Fatalf("frame %d after the dial, want ACK", typ)
	}
	b := openStream(func(up io.Reader, down io.Writer) {
		srv.resume(AppendResume(nil, testSID, 0)[1:], "k", up, down, nil)
	})
	WriteFrame(b.upW, FrameData, []byte("new"))
	got := make([]byte, 3)
	if _, err := io.ReadFull(tc, got); err != nil || string(got) != "new" {
		t.Fatalf("target got %q (%v)", got, err)
	}
	WriteFrame(a.upW, FrameData, []byte("stale"))
	select {
	case <-a.done:
	case <-time.After(2 * time.Second):
		t.Fatal("the replaced stream went on")
	}
	WriteFrame(b.upW, FrameData, []byte("er"))
	got = make([]byte, 2)
	if _, err := io.ReadFull(tc, got); err != nil || string(got) != "er" {
		t.Fatalf("after a stale write the target got %q (%v): the replaced stream reached it", got, err)
	}
	WriteFrame(b.upW, FrameEnd, nil)
}

// With the table full, a flow that loses its stream ends as it did before
// there were sessions.
func TestSessionNotKeptPastLimit(t *testing.T) {
	addr, conn := resumeTarget(t)
	srv := &Server{AllowPrivate: true, ResumeGrace: time.Minute, ResumeMaxKept: 1}
	srv.sess.kept.Store(1)
	a := openStream(func(up io.Reader, down io.Writer) {
		srv.tcpSession(context.Background(), addr, sessKey{"k", testSID}, up, down, nil)
	})
	tc := conn()
	a.kill()
	if !targetClosed(tc, 2*time.Second) {
		t.Fatal("the flow was kept although the table was full")
	}
}

func TestAckBuf(t *testing.T) {
	var b AckBuf
	b.Append([]byte("abcdef"))
	if b.Ack(7) || b.Base() != 0 {
		t.Fatal("an offset past the end was taken")
	}
	if !b.Ack(2) || b.Base() != 2 || b.End() != 6 {
		t.Fatalf("after Ack(2): base %d end %d", b.Base(), b.End())
	}
	if b.Ack(1) {
		t.Fatal("an offset before the base was taken")
	}
	b.Append([]byte("gh"))
	if p, ok := b.From(4); !ok || string(p) != "efgh" {
		t.Fatalf("From(4) = %q %v", p, ok)
	}
	if !b.Ack(8) || b.Len() != 0 || b.Base() != 8 {
		t.Fatal("Ack to the end did not empty the buffer")
	}
}

func TestSessionExt(t *testing.T) {
	body, _ := AppendAddr([]byte{NetTCP}, "example.com:443")
	plain := body
	_, rest, err := ParseAddr(plain[1:])
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ParseSessionExt(rest); ok {
		t.Fatal("found a session in a plain OPEN")
	}
	// An option this build does not know, then the session.
	body = append(body, 9, 3, 'x', 'y', 'z')
	body = AppendSessionExt(body, testSID)
	_, rest, err = ParseAddr(body[1:])
	if err != nil {
		t.Fatal(err)
	}
	if sid, ok := ParseSessionExt(rest); !ok || sid != testSID {
		t.Fatalf("session %x %v", sid, ok)
	}
	if _, ok := ParseSessionExt([]byte{OpenExtSession, 16, 1, 2}); ok {
		t.Fatal("a cut-off option was taken")
	}
}
