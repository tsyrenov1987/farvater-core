package wire

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// realityVersion is the client version a REALITY server reads from the
// session ID (servers may set a minimum): that of the Xray release whose
// REALITY client this one matches.
var realityVersion = [3]byte{26, 3, 27}

var errNotREALITY = errors.New("reality: the server's certificate is not the path's (wrong key, or not a REALITY server)")

// handshakeREALITY runs the client side of REALITY over c. It is a TLS 1.3
// handshake with the path's fingerprint whose session ID carries the
// client's version, the time and the short ID, sealed under a key derived
// from the X25519 exchange between the client's key share and the server's
// public key. The server answers with a temporary certificate whose
// signature is an HMAC under that key; any other certificate fails the dial.
func handshakeREALITY(ctx context.Context, c net.Conn, s PathSpec) (*utls.UConn, error) {
	serverKey, err := ecdh.X25519().NewPublicKey(s.PublicKey)
	if err != nil {
		return nil, errors.New("reality: bad public key")
	}
	var authKey []byte
	cfg := &utls.Config{
		ServerName:             s.SNI,
		InsecureSkipVerify:     true, // the certificate is checked below, against the shared key
		SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 || authKey == nil {
				return errNotREALITY
			}
			cert, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return errNotREALITY
			}
			pub, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return errNotREALITY
			}
			mac := hmac.New(sha512.New, authKey)
			mac.Write(pub)
			if !hmac.Equal(mac.Sum(nil), cert.Signature) {
				return errNotREALITY
			}
			return nil
		},
	}
	if cfg.ServerName == "" {
		cfg.ServerName = s.Host
	}
	u := utls.UClient(c, cfg, clientHello(s.Fingerprint))
	if err := u.BuildHandshakeState(); err != nil {
		return nil, err
	}
	hello := u.HandshakeState.Hello
	keys := u.HandshakeState.State13.KeyShareKeys
	if keys == nil || (keys.Ecdhe == nil && keys.MlkemEcdhe == nil) {
		return nil, errors.New("reality: the fingerprint offers no TLS 1.3 key share")
	}
	ecdhe := keys.Ecdhe
	if ecdhe == nil {
		ecdhe = keys.MlkemEcdhe
	}
	shared, err := ecdhe.ECDH(serverKey)
	if err != nil {
		return nil, err
	}
	if authKey, err = hkdf.Key(sha256.New, shared, hello.Random[:20], "REALITY", 32); err != nil {
		return nil, err
	}

	// The session ID sits at a fixed place in the raw ClientHello (after the
	// 4-byte handshake header, the version and the random, and its length
	// byte). It is zeroed there first: the raw message is the AEAD's
	// additional data.
	const sessionIDAt = 4 + 2 + 32 + 1
	sid := make([]byte, 32)
	copy(hello.Raw[sessionIDAt:], sid)
	copy(sid, realityVersion[:])
	binary.BigEndian.PutUint32(sid[4:], uint32(time.Now().Unix()))
	copy(sid[8:16], s.ShortID)
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aead.Seal(sid[:0], hello.Random[20:], sid[:16], hello.Raw)
	hello.SessionId = sid
	copy(hello.Raw[sessionIDAt:], sid)

	if err := u.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return u, nil
}
