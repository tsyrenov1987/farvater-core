package wire

import (
	"bytes"
	"io"
	"testing"
)

func TestFlexBufGrowsUnderLoadAndShrinksWhenDry(t *testing.T) {
	b := NewFlexBuf(16 << 10)
	defer b.Release()
	if got := len(b.Buf()); got != smallBufSize {
		t.Fatalf("idle buffer %d, want %d", got, smallBufSize)
	}
	b.Done(100) // a trickle stays small
	if got := len(b.Buf()); got != smallBufSize {
		t.Fatalf("after a short read %d, want %d", got, smallBufSize)
	}
	b.Done(smallBufSize) // filled: data pours
	if got := len(b.Buf()); got != 16<<10 {
		t.Fatalf("after a full read %d, want %d", got, 16<<10)
	}
	b.Done(16 << 10)
	if got := len(b.Buf()); got != 16<<10 {
		t.Fatalf("still pouring %d, want %d", got, 16<<10)
	}
	b.Done(10) // dry again
	if b.big != nil || len(b.Buf()) != smallBufSize {
		t.Fatalf("dry read kept the big buffer")
	}
}

func TestFlexBufSmallMaxNeverGrows(t *testing.T) {
	b := NewFlexBuf(smallBufSize)
	defer b.Release()
	b.Done(smallBufSize)
	if b.big != nil {
		t.Fatal("max == small size took a big buffer")
	}
}

// pumpDown must deliver every byte unchanged across the switches between the
// small and the big buffer.
func TestPumpDownFlexBufIntact(t *testing.T) {
	src := make([]byte, 1<<20+123)
	for i := range src {
		src[i] = byte(i * 7)
	}
	// Alternate big chunks and dribbles so the buffer switches both ways.
	r := &chunky{data: src, sizes: []int{40 << 10, 5, 9000, 1, 32 << 10, 300}}
	var out bytes.Buffer
	if err := pumpDown(r, &out, nopMeter{}, nil); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), src) {
		t.Fatal("pumpDown changed the stream")
	}
}

type chunky struct {
	data  []byte
	sizes []int
	i     int
}

func (c *chunky) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := c.sizes[c.i%len(c.sizes)]
	c.i++
	if n > len(p) {
		n = len(p)
	}
	if n > len(c.data) {
		n = len(c.data)
	}
	copy(p, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}
