package wire

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// tlsEcho is a TLS 1.3 server that returns what it reads: the inner TLS a
// browser speaks through the path, which is what makes Vision go direct.
func tlsEcho(t *testing.T) int {
	t.Helper()
	certPEM, keyPEM := selfSigned(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
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
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// sessionConn is the app's end of a flow: what it writes goes up the session,
// what the session delivers comes back on Read.
type sessionConn struct {
	up chan<- []byte
	pr *io.PipeReader
}

func (c *sessionConn) Write(p []byte) (int, error) {
	c.up <- append([]byte(nil), p...)
	return len(p), nil
}
func (c *sessionConn) Read(p []byte) (int, error)       { return c.pr.Read(p) }
func (c *sessionConn) Close() error                     { close(c.up); return nil }
func (c *sessionConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *sessionConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *sessionConn) SetDeadline(time.Time) error      { return nil }
func (c *sessionConn) SetReadDeadline(time.Time) error  { return nil }
func (c *sessionConn) SetWriteDeadline(time.Time) error { return nil }

// A TLS 1.3 session inside a Vision flow, the way a browser uses it: after
// the handshake Vision goes direct, and every later write — several small
// ones, then one larger than a padded frame — must reach the far end intact.
func TestVisionCarriesInnerTLSAfterDirect(t *testing.T) {
	if raceOn {
		t.Skip("Xray's VLESS inbound does uintptr arithmetic that -race's checkptr rejects; run without -race")
	}
	port := xrayVLESS(t, "xtls-rprx-vision")
	spec, err := ParseURI(fmt.Sprintf("vless://%s@127.0.0.1:%d?security=tls&sni=farvater.test&allowInsecure=1&type=tcp&flow=xtls-rprx-vision#t", testUUID, port))
	if err != nil {
		t.Fatal(err)
	}
	w, err := Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sess, err := w.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	up := make(chan []byte, 16)
	pr, pw := io.Pipe()
	target := Target{Host: "127.0.0.1", Port: tlsEcho(t)}
	go func() {
		_, _ = sess.Run(ctx, target, nil, up, pw, nopMeter{})
		pw.Close()
	}()
	c := tls.Client(&sessionConn{up: up, pr: pr}, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := c.HandshakeContext(ctx); err != nil {
		t.Fatalf("inner handshake: %v", err)
	}
	msgs := [][]byte{[]byte("first"), []byte("second"), []byte("third"), bytes.Repeat([]byte("x"), 20000)}
	for i, m := range msgs {
		if _, err := c.Write(m); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		got := make([]byte, len(m))
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatalf("echo %d: %v", i, err)
		}
		if !bytes.Equal(got, m) {
			t.Fatalf("echo %d: got %d bytes that differ from what was sent", i, len(got))
		}
	}
}
