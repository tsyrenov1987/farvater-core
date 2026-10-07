package wire

import (
	"bufio"
	"bytes"
	"net"
	"testing"
	"time"
)

// discardConn is a net.Conn whose writes vanish and whose reads block; the ws
// frame-length tests never reach a read or a write on it.
type discardConn struct{}

func (discardConn) Read([]byte) (int, error)         { select {} }
func (discardConn) Write(p []byte) (int, error)      { return len(p), nil }
func (discardConn) Close() error                     { return nil }
func (discardConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (discardConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (discardConn) SetDeadline(time.Time) error      { return nil }
func (discardConn) SetReadDeadline(time.Time) error  { return nil }
func (discardConn) SetWriteDeadline(time.Time) error { return nil }

// readFrame feeds raw frame bytes to a wsConn and returns what Read does. It
// must never panic: a hostile length may not crash the client.
func readFrame(t *testing.T, raw []byte) error {
	t.Helper()
	w := &wsConn{conn: discardConn{}, br: bufio.NewReader(bytes.NewReader(raw))}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Read panicked on a hostile frame: %v", r)
		}
	}()
	_, err := w.Read(make([]byte, 4096))
	return err
}

func TestWSRejectsHostileFrameLengths(t *testing.T) {
	cases := map[string][]byte{
		// Binary frame, 8-byte length 0xFFFF…FF: overflows int64 to -1, so the
		// unguarded make([]byte, n) panics.
		"int64 overflow": {0x82, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		// Binary frame claiming ~9.2e18 bytes: the unguarded path tries to
		// allocate it.
		"huge binary": {0x82, 0x7F, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		// Ping (control) frame declaring 200 bytes: RFC 6455 caps control
		// frames at 125.
		"oversized control": {0x89, 0x7E, 0x00, 0xC8},
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if err := readFrame(t, raw); err == nil {
				t.Fatal("expected an error for a hostile frame length, got nil")
			}
		})
	}
}
