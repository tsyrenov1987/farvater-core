package main

import (
	"crypto/tls"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// listenPlain is the cleartext listener kilvaterd serves on behind a proxy.
// "unix:/path" is a unix socket (a stale one from a past run is removed first,
// and the socket is group-readable so the proxy's user can reach it); anything
// else is a TCP address.
func listenPlain(addr string) (net.Listener, error) {
	if path, ok := strings.CutPrefix(addr, "unix:"); ok {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		ln, err := net.Listen("unix", path)
		if err != nil {
			return nil, err
		}
		if err := os.Chmod(path, 0o660); err != nil {
			ln.Close()
			return nil, err
		}
		return ln, nil
	}
	return net.Listen("tcp", addr)
}

// warnIfExposed logs if a cleartext (h2c) listener would take connections from
// outside the host. Behind a proxy the socket must be a unix socket or a
// loopback address; a wider bind serves the tunnel unencrypted to anyone who
// reaches the port.
func warnIfExposed(addr string) {
	if strings.HasPrefix(addr, "unix:") {
		return
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		log.Printf("warning: -h2c with -listen %q serves cleartext HTTP/2 on all interfaces; bind a loopback address or a unix: socket so only the local proxy can reach it", addr)
		return
	}
	if ip, err := netip.ParseAddr(host); err != nil || !ip.IsLoopback() {
		log.Printf("warning: -h2c with -listen %q serves cleartext HTTP/2 off the loopback; put it on 127.0.0.1, ::1 or a unix: socket so only the local proxy can reach it", addr)
	}
}

// handshakeListener finishes the TLS handshake before net/http sees a
// connection. Given a raw *tls.Conn, net/http answers a plain-HTTP request
// with its own "Client sent an HTTP request to an HTTPS server." — a line
// only a Go server writes, so a scanner could tell kilvaterd apart from the
// site it stands in for. Here a connection whose handshake fails is closed
// without a word, which is what most TLS-only servers do.
// listenTLS is the listener kilvaterd serves on. onFail, if set, is called
// each time a TLS handshake does not complete, for the handshake-failure metric.
func listenTLS(addr string, cfg *tls.Config, onFail func()) (net.Listener, error) {
	raw, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return newHandshakeListener(raw, cfg, 10*time.Second, onFail), nil
}

type handshakeListener struct {
	net.Listener
	cfg     *tls.Config
	timeout time.Duration
	onFail  func()

	conns   chan net.Conn
	errc    chan error
	done    chan struct{}
	closing sync.Once
}

func newHandshakeListener(inner net.Listener, cfg *tls.Config, timeout time.Duration, onFail func()) *handshakeListener {
	l := &handshakeListener{
		Listener: inner,
		cfg:      cfg,
		timeout:  timeout,
		onFail:   onFail,
		conns:    make(chan net.Conn),
		errc:     make(chan error, 1),
		done:     make(chan struct{}),
	}
	go l.serve()
	return l
}

func (l *handshakeListener) serve() {
	for {
		raw, err := l.Listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			select {
			case l.errc <- err:
			case <-l.done:
			}
			return
		}
		// one slow client must not hold up the others
		go l.handshake(raw)
	}
}

func (l *handshakeListener) handshake(raw net.Conn) {
	tc := tls.Server(raw, l.cfg)
	raw.SetDeadline(time.Now().Add(l.timeout))
	if err := tc.Handshake(); err != nil {
		if l.onFail != nil {
			l.onFail()
		}
		raw.Close()
		return
	}
	raw.SetDeadline(time.Time{})
	select {
	case l.conns <- tc:
	case <-l.done:
		tc.Close()
	}
}

func (l *handshakeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case err := <-l.errc:
		return nil, err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *handshakeListener) Close() error {
	l.closing.Do(func() { close(l.done) })
	return l.Listener.Close()
}
