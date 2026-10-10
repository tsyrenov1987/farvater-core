package main

import (
	"crypto/tls"
	"net"
	"sync"
	"time"
)

// handshakeListener finishes the TLS handshake before net/http sees a
// connection. Given a raw *tls.Conn, net/http answers a plain-HTTP request
// with its own "Client sent an HTTP request to an HTTPS server." — a line
// only a Go server writes, so a scanner could tell kilvaterd apart from the
// site it stands in for. Here a connection whose handshake fails is closed
// without a word, which is what most TLS-only servers do.
// listenTLS is the listener kilvaterd serves on.
func listenTLS(addr string, cfg *tls.Config) (net.Listener, error) {
	raw, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return newHandshakeListener(raw, cfg, 10*time.Second), nil
}

type handshakeListener struct {
	net.Listener
	cfg     *tls.Config
	timeout time.Duration

	conns   chan net.Conn
	errc    chan error
	done    chan struct{}
	closing sync.Once
}

func newHandshakeListener(inner net.Listener, cfg *tls.Config, timeout time.Duration) *handshakeListener {
	l := &handshakeListener{
		Listener: inner,
		cfg:      cfg,
		timeout:  timeout,
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
