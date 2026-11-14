package wire

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"golang.org/x/net/http2"
)

// Writes made while nobody reads come out joined, in reads of at most a piece.
func TestH2BodyGathers(t *testing.T) {
	b := newH2Body(h2BodyPiece)
	want := make([]byte, 40000)
	for i := range want {
		want[i] = byte(i)
	}
	for off := 0; off < len(want); off += 1000 {
		if _, err := b.Write(want[off : off+1000]); err != nil {
			t.Fatal(err)
		}
	}
	b.Close()
	r := h2BodyReader{b}
	var got []byte
	var sizes []int
	buf := make([]byte, 16384)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			sizes = append(sizes, n)
			got = append(got, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the bytes read are not the bytes written")
	}
	if len(sizes) != 3 || sizes[0] != h2BodyPiece || sizes[1] != h2BodyPiece {
		t.Fatalf("reads of %v, want two of %d and the rest", sizes, h2BodyPiece)
	}
}

// A writer waits once h2BodyHold is unread and goes on when the reader takes
// some; the reader's Close fails the writer, the writer's error reaches the reader.
func TestH2BodyBackpressureAndClose(t *testing.T) {
	b := newH2Body(h2BodyPiece)
	r := h2BodyReader{b}
	done := make(chan error, 1)
	go func() {
		_, err := b.Write(make([]byte, h2BodyHold+5000))
		done <- err
	}()
	n, err := io.ReadFull(r, make([]byte, h2BodyHold+5000))
	if err != nil || n != h2BodyHold+5000 {
		t.Fatalf("read %d, %v", n, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	r.Close()
	if _, err := b.Write([]byte("x")); err != io.ErrClosedPipe {
		t.Fatalf("write after the reader closed: %v", err)
	}

	b = newH2Body(h2BodyPiece)
	b.CloseWithError(io.ErrUnexpectedEOF)
	if _, err := (h2BodyReader{b}).Read(make([]byte, 1)); err != io.ErrUnexpectedEOF {
		t.Fatalf("read after CloseWithError: %v", err)
	}
}

type h2RecConn struct {
	net.Conn
	out bytes.Buffer
}

func (c *h2RecConn) Write(p []byte) (int, error) { return c.out.Write(p) }

// The shaper holds WINDOW_UPDATEs until they add up to half the window, and
// then sends the sum; the opening connection update passes at once.
func TestH2ShaperHoldsWindowUpdates(t *testing.T) {
	c := &h2RecConn{}
	s := newH2Shaper(c, chromeH2)
	wu := func(id, inc uint32) []byte {
		return binary.BigEndian.AppendUint32(appendFrameHeader(nil, 4, h2FrameWindowUpdate, 0, id), inc)
	}
	s.Write([]byte(http2.ClientPreface))
	c.out.Reset()

	s.Write(wu(0, chromeH2.connWindow))
	if !bytes.Equal(c.out.Bytes(), wu(0, chromeH2.connWindow)) {
		t.Fatal("the opening connection WINDOW_UPDATE did not pass as it is")
	}
	c.out.Reset()

	s.streams[1] = &h2ShapedStream{}
	limit := chromeH2.streamWindow / 2
	var sum uint32
	for sum+4096 < limit {
		s.Write(wu(1, 4096))
		sum += 4096
	}
	if c.out.Len() != 0 {
		t.Fatalf("%d bytes written below half the window", c.out.Len())
	}
	s.Write(wu(1, 4096))
	if !bytes.Equal(c.out.Bytes(), wu(1, sum+4096)) {
		t.Fatalf("got % x, want one update of %d", c.out.Bytes(), sum+4096)
	}
	c.out.Reset()

	// What was held for a stream goes with the stream.
	s.Write(wu(1, 4096))
	s.ended(1, true, true)
	if len(s.held) != 0 {
		t.Fatal("an ended stream left a held update")
	}
	// A stream the shaper does not follow is not held.
	s.Write(wu(7, 4096))
	if !bytes.Equal(c.out.Bytes(), wu(7, 4096)) {
		t.Fatal("an update on an unknown stream was held")
	}
}
