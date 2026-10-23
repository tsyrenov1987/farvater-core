package wire

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Shadowsocks AEAD (SIP004), TCP only, written from the spec
// (shadowsocks.org/doc/aead.html): the stream is a salt, then chunks of a
// sealed 2-byte length and the sealed payload, each seal with its own nonce
// counter; the first payload starts with the SOCKS-style target address.
// Shadowsocks 2022 and plugins are not carried.

// ssCiphers: key (and salt) size and AEAD constructor by method name.
var ssCiphers = map[string]struct {
	size int
	aead func(key []byte) (cipher.AEAD, error)
}{
	"aes-128-gcm":             {16, ssGCM},
	"aes-256-gcm":             {32, ssGCM},
	"chacha20-ietf-poly1305":  {32, chacha20poly1305.New},
	"chacha20-poly1305":       {32, chacha20poly1305.New},
	"xchacha20-ietf-poly1305": {32, chacha20poly1305.NewX},
}

func ssGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// ssMaxPayload is the largest payload one chunk carries (0x3FFF).
const ssMaxPayload = 0x3FFF

// ssKey is OpenSSL's EVP_BytesToKey with MD5 and no salt, as every
// Shadowsocks implementation derives the master key from the password.
func ssKey(password string, size int) []byte {
	var key, prev []byte
	for len(key) < size {
		h := md5.New()
		h.Write(prev)
		h.Write([]byte(password))
		prev = h.Sum(nil)
		key = append(key, prev...)
	}
	return key[:size]
}

func ssSubkey(key, salt []byte) []byte {
	sub := make([]byte, len(key))
	io.ReadFull(hkdf.New(sha1.New, key, salt, []byte("ss-subkey")), sub)
	return sub
}

type ssWire struct {
	spec PathSpec
	key  []byte
	size int
	aead func([]byte) (cipher.AEAD, error)
}

func newShadowsocks(spec PathSpec) (*ssWire, error) {
	c, ok := ssCiphers[spec.Cipher]
	if !ok {
		return nil, fmt.Errorf("shadowsocks: method %q is not supported", spec.Cipher)
	}
	if spec.Password == "" {
		return nil, errors.New("shadowsocks: missing password")
	}
	return &ssWire{spec: spec, key: ssKey(spec.Password, c.size), size: c.size, aead: c.aead}, nil
}

func (w *ssWire) ID() string           { return w.spec.ID }
func (w *ssWire) Spec() PathSpec       { return w.spec }
func (w *ssWire) NeedsHandshake() bool { return false }
func (w *ssWire) Close() error         { return nil }

func (w *ssWire) Dial(ctx context.Context) (Session, error) {
	c, err := dialTCP(ctx, w.spec.Host, w.spec.Port)
	if err != nil {
		return nil, err
	}
	return &ssSession{conn: &ssConn{Conn: c, w: w}}, nil
}

type ssSession struct{ conn *ssConn }

func (s *ssSession) Close() error { return s.conn.Close() }

func (s *ssSession) Run(ctx context.Context, target Target, prelude []byte, up <-chan []byte, down io.Writer, m Meter) (Outcome, error) {
	head, err := appendSocksAddr(nil, target)
	if err != nil {
		s.conn.Close()
		return OutcomeError, err
	}
	// The address and the first payload leave in one chunk, as clients do.
	if _, err := s.conn.Write(append(head, prelude...)); err != nil {
		s.conn.Close()
		return OutcomeError, err
	}
	return runStream(ctx, s.conn, s.conn, s.conn, up, down, m)
}

// ssConn seals what is written and opens what is read; each direction makes
// its AEAD on its first use, from its own salt.
type ssConn struct {
	net.Conn
	w *ssWire

	wmu    sync.Mutex
	enc    cipher.AEAD
	wnonce []byte

	rmu    sync.Mutex
	dec    cipher.AEAD
	rnonce []byte
	rbuf   []byte // opened payload not yet read
}

func ssIncrement(n []byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

func (c *ssConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	var out []byte
	if c.enc == nil {
		salt := make([]byte, c.w.size)
		if _, err := rand.Read(salt); err != nil {
			return 0, err
		}
		a, err := c.w.aead(ssSubkey(c.w.key, salt))
		if err != nil {
			return 0, err
		}
		c.enc, c.wnonce = a, make([]byte, a.NonceSize())
		out = salt
	}
	n := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > ssMaxPayload {
			chunk = chunk[:ssMaxPayload]
		}
		out = c.enc.Seal(out, c.wnonce, []byte{byte(len(chunk) >> 8), byte(len(chunk))}, nil)
		ssIncrement(c.wnonce)
		out = c.enc.Seal(out, c.wnonce, chunk, nil)
		ssIncrement(c.wnonce)
		p = p[len(chunk):]
		n += len(chunk)
	}
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
	}
	return n, nil
}

func (c *ssConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(c.rbuf) == 0 {
		if err := c.open(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

// open reads and opens the next chunk into rbuf (the server's salt first).
func (c *ssConn) open() error {
	if c.dec == nil {
		salt := make([]byte, c.w.size)
		if _, err := io.ReadFull(c.Conn, salt); err != nil {
			return err
		}
		a, err := c.w.aead(ssSubkey(c.w.key, salt))
		if err != nil {
			return err
		}
		c.dec, c.rnonce = a, make([]byte, a.NonceSize())
	}
	over := c.dec.Overhead()
	lb := make([]byte, 2+over)
	if _, err := io.ReadFull(c.Conn, lb); err != nil {
		return err
	}
	l, err := c.dec.Open(lb[:0], c.rnonce, lb, nil)
	if err != nil {
		return errors.New("shadowsocks: bad chunk (wrong password or method?)")
	}
	ssIncrement(c.rnonce)
	size := (int(l[0])<<8 | int(l[1])) & ssMaxPayload
	b := make([]byte, size+over)
	if _, err := io.ReadFull(c.Conn, b); err != nil {
		return err
	}
	if c.rbuf, err = c.dec.Open(b[:0], c.rnonce, b, nil); err != nil {
		return errors.New("shadowsocks: bad chunk")
	}
	ssIncrement(c.rnonce)
	return nil
}

// SetDeadline and friends reach the TCP connection underneath.
var _ net.Conn = (*ssConn)(nil)

// parseShadowsocks reads the part after ss:// in SIP002's form
// (userinfo@host:port, userinfo the base64 or the percent-encoding of
// method:password) or the older base64 of method:password@host:port.
func parseShadowsocks(rest string) (PathSpec, error) {
	rest, name, _ := strings.Cut(rest, "#")
	rest, query, _ := strings.Cut(rest, "?")
	rest = strings.TrimSuffix(rest, "/")
	if q, _ := url.ParseQuery(query); q.Get("plugin") != "" {
		return PathSpec{}, errors.New("shadowsocks: plugins are not supported")
	}
	if !strings.Contains(rest, "@") {
		b, err := ssBase64(rest)
		if err != nil {
			return PathSpec{}, fmt.Errorf("shadowsocks: %w", err)
		}
		rest = string(b)
	}
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return PathSpec{}, errors.New("shadowsocks: missing host")
	}
	user, hostport := rest[:at], rest[at+1:]
	if !strings.Contains(user, ":") {
		b, err := ssBase64(user)
		if err != nil {
			return PathSpec{}, fmt.Errorf("shadowsocks userinfo: %w", err)
		}
		user = string(b)
	} else if u, err := url.PathUnescape(user); err == nil {
		user = u
	}
	method, password, ok := strings.Cut(user, ":")
	if !ok {
		return PathSpec{}, errors.New("shadowsocks: userinfo is not method:password")
	}
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return PathSpec{}, fmt.Errorf("host:port: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return PathSpec{}, fmt.Errorf("port: %w", err)
	}
	spec := PathSpec{Kind: KindShadowsocks, Host: host, Port: port, Cipher: strings.ToLower(method), Password: password, ID: hostport}
	if n, err := url.PathUnescape(name); err == nil && n != "" {
		spec.ID = n
	}
	if _, ok := ssCiphers[spec.Cipher]; !ok {
		return spec, fmt.Errorf("shadowsocks: method %q is not supported", method)
	}
	return spec, nil
}

// ssBase64 decodes standard or URL-safe base64, padded or not.
func ssBase64(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}
