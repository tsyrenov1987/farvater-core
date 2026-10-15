package wire

import (
	"net"
	"testing"
)

// A freeze cuts the path's stream at a TCP segment: inside a record.
func TestRecordConnTellsACutRecord(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := &recordConn{Conn: a}
	rec := append([]byte{23, 3, 3, 0, 100}, make([]byte, 100)...)
	read := func(p []byte) {
		go b.Write(p)
		if _, err := c.Read(make([]byte, len(p))); err != nil {
			t.Fatal(err)
		}
	}
	read(rec)
	if c.inRecord() {
		t.Fatal("a whole record reads as cut")
	}
	read(rec[:40])
	if !c.inRecord() {
		t.Fatal("40 bytes of a 105-byte record read as whole")
	}
	read(rec[40:])
	if c.inRecord() {
		t.Fatal("the rest of the record did not close it")
	}
	read([]byte("GET / HTTP/1.1\r\n"))
	if c.inRecord() {
		t.Fatal("a stream that is not TLS reads as a cut record")
	}
}
